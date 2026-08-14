"""Deterministic bounded decoder smoke fuzz."""
import pathlib, random, sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'reference'))
import r8session as s
def run(seed=0x52385345):
 r=random.Random(seed)
 for size in range(1282):
  try: s.decode(r.randbytes(size))
  except s.SessionError as e: assert e.category in s.ERRORS
  except Exception as e: raise AssertionError(f'uncategorized {e!r}') from e
if __name__=='__main__': run()
