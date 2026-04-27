/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * When set to the literal string `'true'` AND the build is in DEV mode,
   * allows the Council dashboard to bypass backend auth using a localStorage
   * flag. ALWAYS unset in production builds. See docs/audit A-031.
   */
  readonly VITE_ALLOW_DEV_BYPASS?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
