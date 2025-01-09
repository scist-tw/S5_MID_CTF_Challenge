import functools
import random
import sys

from secret import FLAG


def strategy(candies: list[int]) -> tuple[int, int]:
    target = functools.reduce(lambda x, y: x ^ y, candies)
    if target == 0:
        while True:
            n = random.randint(1, len(candies))
            if candies[n - 1] > 0:
                k = random.randint(1, candies[n - 1])
                return n, k

    for idx, candy in enumerate(candies, 1):
        result = candy - (candy ^ target)
        if result > 0:
            return idx, result

    raise ValueError("Strategy implements wrong.")

def main():
    print("Trick or Treat!!")
    print("There are some candy in the boxes, your mission is to get the last one candy of all boxes.")
    print("In each turn, you can take one or more candy from one of the boxes, and my turn comes next.")
    print("If you pass one hundred challenges, I'll give you the biggest candy which is the flag.")
    for counter in range(1, 101):
        print(f"========== Challenge {counter} / 100 ==========")
        candies: list[int] = [random.getrandbits(8) for _ in range(counter + 1)]
        print(f"There are {counter + 1} boxes, each contains {', '.join(map(str, candies))} candy.")
        your_turn: bool = False
        while sum(candies) > 0:
            your_turn = not your_turn
            if your_turn:
                data = input("It's your turn, entering (n, k) denotes to take k candy from the box n: ")
                n, k = tuple(map(int, data.strip("()\n").split(",")))
                if n <= 0 or k <= 0 or candies[n - 1] < k:
                    print("Bad hacker")
                    raise ValueError("Wrong input.")
                print(f"You take {k} candy from the box {n}.")
            else:
                n, k = strategy(candies)
                print(f"Then, I take {k} candy from the box {n}.")
            candies[n - 1] -= k

        if your_turn is False:
            print("Oh, you failed.")
            raise ValueError("Mission failed.")

        print("Mission succeeded.")

    print(f"Congratulations, here's your flag: {FLAG}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(error)
        sys.exit(1)
