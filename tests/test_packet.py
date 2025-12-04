import struct
from typing import get_args
from unittest import SkipTest

import av

from .common import fate_suite, sandboxed


class TestProperties:
    def test_is_keyframe(self) -> None:
        with av.open(fate_suite("h264/interlaced_crop.mp4")) as container:
            stream = container.streams.video[0]
            for i, packet in enumerate(container.demux(stream)):
                if i in (0, 21, 45, 69, 93, 117):
                    assert packet.is_keyframe
                else:
                    assert not packet.is_keyframe

    def test_is_corrupt(self) -> None:
        with av.open(fate_suite("mov/white_zombie_scrunch-part.mov")) as container:
            stream = container.streams.video[0]
            for i, packet in enumerate(container.demux(stream)):
                if i == 65:
                    assert packet.is_corrupt
                else:
                    assert not packet.is_corrupt

    def test_is_discard(self) -> None:
        with av.open(fate_suite("mov/mov-1elist-ends-last-bframe.mov")) as container:
            stream = container.streams.video[0]
            for i, packet in enumerate(container.demux(stream)):
                if i == 46:
                    assert packet.is_discard
                else:
                    assert not packet.is_discard

    def test_is_disposable(self) -> None:
        with av.open(fate_suite("hap/HAPQA_NoSnappy_127x1.mov")) as container:
            stream = container.streams.video[0]
            for i, packet in enumerate(container.demux(stream)):
                if i == 0:
                    assert packet.is_disposable
                else:
                    assert not packet.is_disposable

    def test_set_duration(self) -> None:
        with av.open(fate_suite("h264/interlaced_crop.mp4")) as container:
            for packet in container.demux():
                assert packet.duration is not None
                old_duration = packet.duration
                packet.duration += 10

                assert packet.duration == old_duration + 10


class TestPacketSideData:
    def test_data_types(self) -> None:
        dtypes = get_args(av.packet.PktSideDataT)

        if av.ffmpeg_version_info.startswith("n") or av.ffmpeg_version_info.count(
            "."
        ) not in (1, 2):
            raise SkipTest(f"Expect version to be SemVar: {av.ffmpeg_version_info}")

        ffmpeg_ver = [int(v) for v in av.ffmpeg_version_info.split(".", 2)[:2]]
        for dtype in dtypes:
            av_enum = av.packet.packet_sidedata_type_from_literal(dtype)
            assert dtype == av.packet.packet_sidedata_type_to_literal(av_enum)

            if (ffmpeg_ver[0] < 8 and dtype == "lcevc") or (
                ffmpeg_ver[0] < 9 and dtype == "rtcp_sr"
            ):
                break

    def test_iter(self) -> None:
        with av.open(fate_suite("h264/extradata-reload-multi-stsd.mov")) as container:
            for pkt in container.demux():
                for sdata in pkt.iter_sidedata():
                    assert pkt.dts == 2 and sdata.data_type == "new_extradata"

    def test_palette(self) -> None:
        with av.open(fate_suite("h264/extradata-reload-multi-stsd.mov")) as container:
            iterpackets = container.demux()
            pkt = next(pkt for pkt in iterpackets if pkt.has_sidedata("new_extradata"))

            sdata = pkt.get_sidedata("new_extradata")
            assert sdata.data_type == "new_extradata"
            assert bool(sdata)
            assert sdata.data_size > 0
            assert sdata.data_desc == "New Extradata"

            nxt = next(iterpackets)  # has no palette

            assert not nxt.has_sidedata("new_extradata")

            sdata1 = nxt.get_sidedata("new_extradata")
            assert sdata1.data_type == "new_extradata"
            assert not bool(sdata1)
            assert sdata1.data_size == 0

            nxt.set_sidedata(sdata, move=True)
            assert not bool(sdata)

    def test_buffer_protocol(self) -> None:
        """Test that PacketSideData supports the buffer protocol and modification."""
        with av.open(fate_suite("h264/extradata-reload-multi-stsd.mov")) as container:
            for pkt in container.demux():
                if pkt.has_sidedata("new_extradata"):
                    sdata = pkt.get_sidedata("new_extradata")

                    # Test bytes()
                    raw = bytes(sdata)
                    assert len(raw) == sdata.data_size
                    assert len(raw) > 0

                    # Test buffer_size and buffer_ptr properties
                    assert sdata.buffer_size == sdata.data_size
                    assert sdata.buffer_ptr != 0

                    # Test memoryview
                    mv = memoryview(sdata)
                    assert len(mv) == sdata.data_size
                    assert bytes(mv) == raw

                    # Test update() modifies data
                    modified = b"\xde\xad\xbe\xef" + raw[4:]
                    sdata.update(modified)
                    assert bytes(sdata)[:4] == b"\xde\xad\xbe\xef"

                    # Test set_sidedata() persists to packet
                    pkt.set_sidedata(sdata)
                    sdata2 = pkt.get_sidedata("new_extradata")
                    assert bytes(sdata2)[:4] == b"\xde\xad\xbe\xef"
                    return

        raise AssertionError("No packet with new_extradata side data found")

    def test_skip_samples_remux(self) -> None:
        """Test remuxing audio with skip_samples side data.

        Note: The muxer may recalculate skip_start from codec delay, so we only
        verify skip_end which represents samples to trim at the end.
        """
        output_path = sandboxed("skip_samples_modified.mkv")
        new_skip_end = 888

        # Read, modify skip_samples, and remux
        with av.open(fate_suite("mkv/codec_delay_opus.mkv")) as inp:
            audio_stream = inp.streams.audio[0]

            with av.open(output_path, "w") as out:
                out_stream = out.add_stream_from_template(audio_stream)

                for pkt in inp.demux(audio_stream):
                    if pkt.dts is None:
                        continue

                    # Modify skip_samples if present
                    if pkt.has_sidedata("skip_samples"):
                        sdata = pkt.get_sidedata("skip_samples")
                        raw = bytes(sdata)
                        # Only modify skip_end (skip_start is recalculated by muxer)
                        new_data = raw[:4] + struct.pack("<I", new_skip_end) + raw[8:]
                        sdata.update(new_data)
                        pkt.set_sidedata(sdata)

                    pkt.stream = out_stream
                    out.mux(pkt)

        # Verify the modification persisted
        with av.open(output_path) as container:
            audio = container.streams.audio[0]
            for pkt in container.demux(audio):
                if pkt.has_sidedata("skip_samples"):
                    sdata = pkt.get_sidedata("skip_samples")
                    raw = bytes(sdata)
                    _, skip_end = struct.unpack("<II", raw[:8])
                    assert skip_end == new_skip_end
                    return

        raise AssertionError("No packet with skip_samples side data found in output")
