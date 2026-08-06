import time

from agent.collector import WindowsCollector


def main():

    collector = WindowsCollector()

    while True:

        try:

            collector.collect()

        except KeyboardInterrupt:

            break

        except Exception as error:

            print(error)

        time.sleep(2)


if __name__ == "__main__":

    main()