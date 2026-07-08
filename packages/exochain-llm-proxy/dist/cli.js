#!/usr/bin/env node
/*
 * Copyright 2026 Exochain Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
const command = process.argv[2];
if (!command || !["openai", "mcp", "receipt-status"].includes(command)) {
    console.error("usage: exochain-llm-proxy <openai|mcp|receipt-status>");
    process.exit(2);
}
for (const required of [
    "EXOCHAIN_GATEWAY_URL",
    "EXOCHAIN_TENANT_ID",
    "EXOCHAIN_NAMESPACE",
    "EXOCHAIN_ACTOR_DID",
    "EXOCHAIN_LYNK_ADAPTER_DID",
    "EXOCHAIN_LYNK_CUSTODY_POLICY_HASH",
    "EXOCHAIN_LYNK_STORAGE_MODE",
    "EXOCHAIN_LYNK_IDEMPOTENCY_KEY",
]) {
    if (!process.env[required]) {
        console.error(`missing required environment variable ${required}`);
        process.exit(2);
    }
}
console.log(JSON.stringify({
    command,
    status: "configured",
    gateway_url: process.env.EXOCHAIN_GATEWAY_URL,
    tenant_id: process.env.EXOCHAIN_TENANT_ID,
    namespace: process.env.EXOCHAIN_NAMESPACE,
    storage_mode: process.env.EXOCHAIN_LYNK_STORAGE_MODE,
}));
export {};
//# sourceMappingURL=cli.js.map