"""Random file to decompile."""


def fibo(n):
    """Generate fibonanci numbers."""
    a, b = 0, 1
    for _ in range(n):
        yield a
        a, b = b, a + b


if __name__ == "__main__":
    print("hello world")
    for num in fibo(20):
        print(num)
