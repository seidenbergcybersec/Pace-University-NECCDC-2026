import ipaddress
import asyncio
import argparse
import platform

SYSTEM = platform.system().lower()


async def ping(host: str, sem: asyncio.Semaphore) -> str | None:
    async with sem:
        if SYSTEM == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", host]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", host]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )

        await proc.communicate()
        return host if proc.returncode == 0 else None


async def main(subnet: str, batch: int):
    network = ipaddress.ip_network(subnet, strict=False)
    sem = asyncio.Semaphore(batch)

    tasks = [
        ping(str(ip), sem)
        for ip in network.hosts()
    ]

    results = await asyncio.gather(*tasks)

    for host in results:
        if host:
            print(host)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("subnet", help="Subnet in CIDR notation (e.g. 192.168.1.0/24)")
    parser.add_argument(
        "-b",
        type=int,
        default=50,
        help="Maximum number of concurrent ping requests"
    )
    args = parser.parse_args()

    asyncio.run(main(args.subnet, args.b))
