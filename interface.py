import threading
import time

class Num:
    def __init__(self):
        self.n = 0



def f(n):
    while True:
        n.n += 1
        #time.sleep(1)


if __name__ == "__main__":
    num = Num()
    th = threading.Thread(target=f, args=(num, ), daemon=True);
    th.start()
    while True:
        i = input()
        if i == 'p':
            print(num.n)
        if i == 'e':
            break