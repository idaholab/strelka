from __future__ import annotations

from . import Options, Scanner
from ..auxiliary import indicators
from ..model import Date, File


class ScanIqy(Scanner):
    """
    Scanner for extracting URLs from IQY (Excel Web Query Internet Inquire) files.

    IQY files are typically used to import data into Excel from the web. They often
    contain URLs that specify the data source. This scanner aims to extract these URLs
    and process them for IOCs.

    The following is a typical format of an IQY file:
    WEB
    1
    [URL]
    [optional parameters]

    Reference for IQY file format:
        https://learn.microsoft.com/en-us/office/vba/api/excel.querytable
    """

    def scan(self, data: bytes, file: File, options: Options, expire_at: Date) -> None:
        """
        Processes the provided IQY data to extract URLs.

        Attempts to decode the data and applies a regex pattern to identify and extract
        URLs. Extracted URLs are added to the scanner's indicators list.

        Args:
            data (bytes): Data associated with the IQY file to be scanned.
            file (File): File object associated with the data.
            options (Options): Options to be applied during the scan.
            expire_at (Date): Expiration timestamp for extracted files.
        """
        self.event.update(
            {
                "address_found": False,
            }
        )

        # Attempt to decode the data
        try:
            decoded_data = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                decoded_data = data.decode("latin-1")
            except UnicodeDecodeError:
                decoded_data = data.decode("ascii")

        # Extract addresses from the data
        addresses = set(
            match.group(0)
            for line in decoded_data.splitlines()
            if (match := indicators.url.search(line))
        )

        # Add extracted URLs to the scanner's IOC list
        if addresses:
            self.event["address_found"] = True
            self.add_related(addresses)
