import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";

const multer = require("../server/node_modules/multer");

// Exercise the installed parser with the limit extracted from each owned
// configuration. These small in-memory fields never open a listener or DB.
const surfaces = [
  { route: "records", field: "file", paths: ["/upload"] },
  {
    route: "credentials",
    field: "card_image",
    paths: ["/insurance", "/advance-directive", "/government-id", "/poa"],
  },
];

for (const surface of surfaces) {
  describe(`${surface.route} upload field limits`, () => {
    const source = fs.readFileSync(
      path.join(process.cwd(), `server/routes/${surface.route}.js`),
      "utf8",
    );
    const configuration = source.match(/const upload = multer\(\{([\s\S]*?)\n\}\);/);
    const limits = configuration?.[1]?.match(/limits:\s*\{([^}]+)\}/)?.[1];
    const configuredIndex = limits?.match(/fieldArrayIndexLimit:\s*(\d+)\b/)?.[1];

    async function parseField(fieldName: string) {
      const boundary = "livesafe-small-field-test";
      const body = Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="${fieldName}"\r\n\r\nvalue\r\n--${boundary}--\r\n`,
      );
      const request = Object.assign(Readable.from([body]), {
        method: "POST",
        headers: {
          "content-type": `multipart/form-data; boundary=${boundary}`,
          "content-length": String(body.length),
        },
        body: {} as Record<string, unknown>,
      });
      let handlerReached = false;
      const error = await new Promise<{ code?: string } | undefined>((resolve) => {
        multer({
          limits: configuredIndex === undefined
            ? {}
            : { fieldArrayIndexLimit: Number(configuredIndex) },
        }).single(surface.field)(request, {}, (failure: { code?: string } | undefined) => {
          if (!failure) handlerReached = true;
          resolve(failure);
        });
      });
      return { error, handlerReached, body: request.body };
    }

    it("sets a finite zero index limit and keeps authentication before every parser", () => {
      expect(configuredIndex).toBe("0");
      expect(source.match(/\bmulter\(\{/g)).toHaveLength(1);
      expect(source.match(/upload\.single\(/g)).toHaveLength(surface.paths.length);
      for (const route of surface.paths) {
        expect(source).toContain(`router.post('${route}', authMiddleware, upload.single(`);
      }
    });

    it("rejects index one before downstream handling", async () => {
      const result = await parseField("probe[1]");
      expect(result.error?.code).toBe("LIMIT_FIELD_ARRAY_INDEX");
      expect(result.handlerReached).toBe(false);
      expect(result.body).toEqual({});
    });

    it("continues to accept the existing flat-field shape", async () => {
      const result = await parseField("document_type");
      expect(result.error).toBeUndefined();
      expect(result.handlerReached).toBe(true);
      expect(result.body).toEqual({ document_type: "value" });
    });
  });
}
