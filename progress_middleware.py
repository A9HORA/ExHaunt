from tqdm import tqdm
from concurrent.futures import as_completed
import logging

class ProgressMiddleware:
    """
    Middleware to provide a progress bar for tasks and optional logging.
    Can wrap over iterables or futures from ThreadPoolExecutor.
    """

    def __init__(self, total=None, desc="Progress", unit="item", disable=False, log_file=None):
        """
        Args:
            total (int): total number of items (optional, inferred if iterable has __len__)
            desc (str): label for the progress bar
            unit (str): unit for items (e.g., 'subdomain', 'file')
            disable (bool): disable progress bar (quiet mode)
            log_file (str): if provided, logs progress updates to this file
        """
        self.total = total
        self.desc = desc
        self.unit = unit
        self.disable = disable
        self.logger = None

        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format="%(asctime)s - %(levelname)s - %(message)s"
            )
            self.logger = logging.getLogger(__name__)
            self.logger.info("Progress tracking started.")

    def wrap_iterable(self, iterable):
        """Wrap any iterable with a progress bar + optional logging."""
        bar = tqdm(iterable, total=self.total, desc=self.desc, unit=self.unit, disable=self.disable)
        for item in bar:
            if self.logger:
                self.logger.info(f"{self.desc}: processed {bar.n}/{bar.total}")
            yield item

    def wrap_futures(self, futures):
        """Wrap futures (from ThreadPoolExecutor) with a progress bar + optional logging."""
        bar = tqdm(as_completed(futures), total=len(futures), desc=self.desc, unit=self.unit, disable=self.disable)
        for f in bar:
            if self.logger:
                self.logger.info(f"{self.desc}: processed {bar.n}/{bar.total}")
            yield f
