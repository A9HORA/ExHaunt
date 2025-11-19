from tqdm import tqdm
from concurrent.futures import as_completed
import logging
import sys

class ProgressMiddleware:
    """
    Progress bar + optional logging that stays pinned at the bottom of the screen.
    All runtime prints should go through .write() to keep the bar anchored.
    """

    def __init__(self, total=None, desc="Progress", unit="item", disable=False, log_file=None):
        self.total = total
        self.desc = desc
        self.unit = unit
        self.disable = disable
        self.logger = None
        self._bar = None
        self._stderr = sys.stderr

        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format="%(asctime)s - %(levelname)s - %(message)s"
            )
            self.logger = logging.getLogger(__name__)
            self.logger.info("Progress tracking started.")

    def start(self):
        """Create the bar immediately so any writes can go above it."""
        if self.disable or self._bar is not None:
            return
        self._bar = tqdm(
            total=self.total,
            desc=self.desc,
            unit=self.unit,
            disable=self.disable,
            leave=True,
            position=0,
            dynamic_ncols=True,
            file=self._stderr,
            mininterval=0.1,
        )

    def write(self, text: str):
        """Print above the bar and keep the bar pinned at the bottom."""
        tqdm.write(text, file=self._stderr)
        if self._bar is not None:
            self._bar.refresh()
        if self.logger:
            try:
                self.logger.info(text)
            except Exception:
                pass

    def wrap_iterable(self, iterable):
        """Manually advance the bar for a regular iterable."""
        if self._bar is None:
            self.start()
        bar = self._bar
        for item in iterable:
            yield item
            if bar is not None:
                bar.update(1)
                if self.logger:
                    self.logger.info(f"{self.desc}: processed {bar.n}/{bar.total}")

    def wrap_futures(self, futures):
        """Advance the pinned bar as futures complete (thread pool)."""
        if self._bar is None:
            self.start()
        bar = self._bar
        for f in as_completed(futures):
            yield f
            if bar is not None:
                bar.update(1)
                if self.logger:
                    self.logger.info(f"{self.desc}: processed {bar.n}/{bar.total}")
