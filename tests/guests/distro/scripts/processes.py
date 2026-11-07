"""Processes: shared memory between handles, and asyncio subprocesses, timeouts and threads."""

import asyncio
import multiprocessing
import multiprocessing.shared_memory


def square(value):
    return value * value


if __name__ == "__main__":
    shared = multiprocessing.shared_memory.SharedMemory(create=True, size=4096)
    shared.buf[:5] = b"hello"
    other = multiprocessing.shared_memory.SharedMemory(name=shared.name)
    print("shared", bytes(other.buf[:5]))
    other.close()
    shared.close()
    shared.unlink()

    async def main():
        process = await asyncio.create_subprocess_exec(
            "/bin/cat", stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE
        )
        output, _ = await process.communicate(b"through cat\n")
        print("asyncio", output, process.returncode)
        try:
            await asyncio.wait_for(asyncio.sleep(10), 0.05)
        except TimeoutError:
            print("asyncio timeout")
        results = await asyncio.gather(*(asyncio.to_thread(square, n) for n in range(5)))
        print("to_thread", results)

    asyncio.run(main())
