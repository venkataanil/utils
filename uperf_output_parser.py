#!/usr/bin/env python3
"""This program parses uperf output which is provided as input file. Before running this program, run uperf tool and capture output to a file and then pass this outout file to this program."""
import argparse
import dataclasses
import datetime
import re
import shlex
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import numpy as np


@dataclasses.dataclass
class RawUperfStat:
    """Represents a raw Uperf statistic outputted through stdout."""

    timestamp: float
    bytes: int
    ops: int


@dataclasses.dataclass
class UperfStdout:
    """
    Represents stdout from a Uperf benchmark run.

    Note that some attributes are included which may not appear in all stdout of Uperf. Within the
    cloud-bulldozer organization, we use benchmark-wrapper with specific profile names that have
    the following format: ``test-proto-wsize-rsize-nthr``. Uperf prints the profile name to stdout, which
    we parse within the benchmark wrapper and store in this class.
    """

    results: Tuple[RawUperfStat, ...]
    duration: int
    test_type: Optional[str] = None
    protocol: Optional[str] = None
    message_size: Optional[int] = None
    read_message_size: Optional[int] = None
    num_threads: Optional[int] = None


@dataclasses.dataclass
class UperfStat:
    """Parsed Uperf Statistic."""

    uperf_ts: str
    timestamp: str
    bytes: int
    norm_byte: int
    ops: int
    norm_ops: int
    norm_ltcy: float
    iteration: Optional[int] = None


class Uperf():
    """Wrapper for the uperf benchmark."""

    def parse_stdout(self, stdout: str) -> UperfStdout:
        """
        Return parsed stdout of Uperf sample.

        Parameters
        ----------
        stdout : str
            Raw stdout from Uperf to parse
        Returns
        -------
        UperfStdout
        """

        # This will effectivly give us:
        # <profile name="{{test}}-{{proto}}-{{wsize}}-{{rsize}}-{{nthr}}">
        profile_name = re.findall(r"running profile:(.*) \.\.\.", stdout)[0]
        print("profile name is ", profile_name)
        vals = profile_name.split("-")
        parsed_profile_name_types: Dict[str, type] = {
            "test_type": str,
            "protocol": str,
            "message_size": int,
            "read_message_size": int,
            "num_threads": int,
        }
        parsed_profile_name: Dict[str, Optional[Union[str, int]]] = {}
        if len(vals) != 5:
            print(
                f"Unable to parse detected profile name: {profile_name}. Expected format of "
                "'test_name-protocol-message_size-read_message_size-num_threads'"
            )
            parsed_profile_name = {key: None for key in parsed_profile_name_types}
        else:
            for i, (key, cast) in enumerate(parsed_profile_name_types.items()):
                parsed_profile_name[key] = cast(vals[i])

        # This will yeild us this structure :
        #     timestamp, number of bytes, number of operations
        # [('1559581000962.0330', '0', '0'), ('1559581001962.8459', '4697358336', '286704') ]
        tx_str = "Txn1" if parsed_profile_name["test_type"] == "connect" else "Txn2"
        results = re.findall(rf"timestamp_ms:(.*) name:{tx_str} nr_bytes:(.*) nr_ops:(.*)", stdout)
        # We assume message_size=write_message_size to prevent breaking dependant implementations

        uperf_stdout = UperfStdout(
            results=tuple(
                RawUperfStat(timestamp=float(r[0]), bytes=int(r[1]), ops=int(r[2])) for r in results
            ),
            duration=len(results),
        )

        for key, value in parsed_profile_name.items():
            setattr(uperf_stdout, key, value)
        return uperf_stdout

    @staticmethod
    def get_results_from_stdout(stdout: UperfStdout) -> List[UperfStat]:
        """
        Return list of results given raw uperf stdout.

        Uperf will output its statistics on newlines as it runs. The goal of this method is to
        return each of those statictics within a :py:class:`UperfStat` instance.
        Parameters
        ----------
        stdout : UperfStdout
            Parsed stdout from Uperf run.
        Returns
        -------
        list of UperfStat
        """

        processed: List[UperfStat] = []
        prev_bytes: int = 0
        prev_ops: int = 0
        prev_timestamp: float = 0.0
        num_bytes: int = 0
        ops: int = 0
        timestamp: float = 0.0
        norm_ops: int = 0
        norm_ltcy: float = 0.0

        for result in stdout.results:
            timestamp, num_bytes, ops = result.timestamp, result.bytes, result.ops

            norm_ops = ops - prev_ops
            if norm_ops != 0 and prev_timestamp != 0.0:
                norm_ltcy = ((timestamp - prev_timestamp) / norm_ops) * 1000

                datapoint = UperfStat(
                    uperf_ts=datetime.datetime.fromtimestamp(int(timestamp) / 1000).isoformat(),
                    timestamp=datetime.datetime.fromtimestamp(int(timestamp) / 1000).isoformat(),
                    bytes=num_bytes,
                    norm_byte=num_bytes - prev_bytes,
                    ops=ops,
                    norm_ops=norm_ops,
                    norm_ltcy=norm_ltcy,
                )

                processed.append(datapoint)
            prev_timestamp, prev_bytes, prev_ops = timestamp, num_bytes, ops

        return processed

    def collect(self, file_name):
        #with open("/home/vkommadi/work/source/perf/k8s-netperf/uperf_output.log", 'r') as file:
        with open(file_name, 'r') as file:
            file_content = file.read()
            # Only show the full output if debug is enabled
            #print(file_content)

            stdout: UperfStdout = self.parse_stdout(file_content)
            result_data: List[UperfStat] = self.get_results_from_stdout(stdout)

            byte_summary = []
            lat_summary = []
            op_summary = []
            for result_datapoint in result_data:
                byte_summary.append(result_datapoint.norm_byte)
                lat_summary.append(result_datapoint.norm_ltcy)
                op_summary.append(result_datapoint.norm_ops)
            print(f"{'-'*50}")
            print(f"Average byte : {np.average(byte_summary)}")
            print(f"Average ops : {np.average(op_summary)}")
            print(f"95%ile Latency(ms) : {np.percentile(lat_summary,95)}")
            print(f"{'-'*50}")


def main():
    parser = argparse.ArgumentParser(description='Parse uperf output from a file.')
    parser.add_argument('uperf_output_file_name', help='uperf output file.')

    args = parser.parse_args()
    Uperf().collect(args.uperf_output_file_name)


if __name__ == "__main__":
    main()
