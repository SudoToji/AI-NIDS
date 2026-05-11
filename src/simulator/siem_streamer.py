"""
SIEM Feed Simulator
===================
Simulates a live SIEM feed (e.g., Zeek logs or Elasticsearch alerts)
by streaming network flow records from a CSV file.
"""

from __future__ import annotations

import os
from typing import Iterator, Dict, Any, Optional

import pandas as pd


class SIEMStreamer:
    """Streams rows from a CSV dataset as if they were live SIEM alerts/logs."""
    
    def __init__(self, file_path: str):
        """
        Initialize the SIEM streamer.
        
        Args:
            file_path: Path to the CSV dataset (e.g., UNSW-NB15)
            
        Raises:
            FileNotFoundError: If the CSV file does not exist.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset not found at {file_path}")
            
        self.file_path = file_path

    def stream_events(self, limit: Optional[int] = None, chunk_size: int = 1000) -> Iterator[Dict[str, Any]]:
        """
        Stream events from the CSV file one by one.
        Uses chunking to handle large files without blowing up memory.
        
        Args:
            limit: Maximum number of events to yield. Yields all if None.
            chunk_size: Number of rows to read into memory at a time.
            
        Yields:
            Dictionary representing a single network flow event.
        """
        yielded_count = 0
        
        # Read the CSV in chunks to be memory-efficient
        for chunk in pd.read_csv(self.file_path, chunksize=chunk_size):
            # Iterate over each row in the chunk
            for _, row in chunk.iterrows():
                if limit is not None and yielded_count >= limit:
                    return
                
                # Yield as a native Python dictionary
                yield row.to_dict()
                yielded_count += 1
