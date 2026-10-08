#!/usr/bin/env node
import { defaultDeps, run } from "./main.js";

process.exitCode = await run(process.argv.slice(2), defaultDeps());
