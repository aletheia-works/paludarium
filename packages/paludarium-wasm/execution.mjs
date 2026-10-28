import { channel, imports } from "./worker-support.mjs";
const port = await channel();
let e;
port.listen(async message => {
  try {
    if (message.type === "probe-go") {
      for (let iteration = 0; iteration < 128; iteration++) {
        const id = e.buffer_new(4096);
        if (!id || e.buffer_set(id, 4095, iteration) !== 0 || e.buffer_get(id, 4095) !== iteration) throw new Error("shared std allocator buffer failed");
        e.buffer_drop(id);
      }
      if (e.shared_space_add(message.space, 1000) !== 0) throw new Error("shared AddressSpace atomic failed");
      port.send({ type: "probe-done", allocations: 128, atomicAdds: 1000 }); return;
    }
    if (message.type === "wait-go") {
      port.send({ type: "wait-starting" });
      const result = e.shared_wait(message.space, 0, 1000);
      port.send({ type: "wait-done", result }); return;
    }
    if (message.type !== "execute") return;
    const diagnostic = WebAssembly.Module.exports(message.module).some(item => item.name === "cost_version");
    const cost = diagnostic ? (field, value) => {
      if (!Number.isSafeInteger(value) || value < 0 || e.cost_add(field, BigInt(value)) !== 0) throw Error("Diagnostic counter rejected");
    } : undefined;
    const instance = await WebAssembly.instantiate(message.module, imports(message.memory, { spawnTask: handle => port.send({ type: "spawn-task", handle }), cost, net: request => port.send({ type: "net", request }) }));
    e = instance.exports;
    const tlsBefore = e.__tls_base.value;
    // Child must not call Rust before it owns a stack and TLS region.
    e.__stack_pointer.value = message.stackTop;
    e.__wasm_init_tls(message.tlsPointer);
    const tlsAfter = e.__tls_base.value;
    const sharedToken = e.buffer_get(message.tokenHandle, 0);
    port.send({ type: "started", diagnostics: { stackTop: e.__stack_pointer.value, tlsBefore, tlsAfter, token: sharedToken, sessionHandle: message.sessionHandle, threadToken: String(e.thread_token()) } });
    if (message.operation === "probe") return;
    if (message.operation === "task") {
      const result = e.host_task_run(message.taskHandle);
      port.send({ type: "task-finished", result }); return;
    }
    const result = e.session_run(message.sessionHandle);
    port.send({ type: "finished", result });
  } catch (error) { port.send({ type: "failed", error: String(error) }); }
});
