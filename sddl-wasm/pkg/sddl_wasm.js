import * as wasm from "./sddl_wasm_bg.wasm";
export * from "./sddl_wasm_bg.js";
import { __wbg_set_wasm } from "./sddl_wasm_bg.js";
__wbg_set_wasm(wasm);