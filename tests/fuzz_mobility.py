import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "reference"))
import r8mobility as m


def run(seed=0x52384D31, cases=2048, maximum_size=256):
    """Bounded parser fuzzing: every malformed input has a finite public category."""
    rng = random.Random(seed)
    for _ in range(cases):
        value = rng.randbytes(rng.randrange(maximum_size + 1))
        try:
            m.parse_control(value)
        except m.MobilityError as error:
            assert error.category in m.CATEGORIES
        except Exception as error:
            raise AssertionError(repr(error)) from error


if __name__ == "__main__":
    run()
