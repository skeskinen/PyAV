cimport libav as lib
from libc.stdint cimport uint8_t

from av.error cimport err_check
from av.video.format cimport VideoFormat
from av.video.frame cimport alloc_video_frame

from enum import IntEnum


class Interpolation(IntEnum):
    FAST_BILINEAR: "Fast bilinear" = SWS_FAST_BILINEAR
    BILINEAR: "Bilinear" = SWS_BILINEAR
    BICUBIC: "Bicubic" = SWS_BICUBIC
    X: "Experimental" = SWS_X
    POINT: "Nearest neighbor / point" = SWS_POINT
    AREA: "Area averaging" = SWS_AREA
    BICUBLIN: "Luma bicubic / chroma bilinear" = SWS_BICUBLIN
    GAUSS: "Gaussian" = SWS_GAUSS
    SINC: "Sinc" = SWS_SINC
    LANCZOS: "Bicubic spline" = SWS_LANCZOS
    SPLINE: "Bicubic spline" = SWS_SPLINE


class Colorspace(IntEnum):
    ITU709 = SWS_CS_ITU709
    FCC = SWS_CS_FCC
    ITU601 = SWS_CS_ITU601
    ITU624 = SWS_CS_ITU624
    SMPTE170M = SWS_CS_SMPTE170M
    SMPTE240M = SWS_CS_SMPTE240M
    DEFAULT = SWS_CS_DEFAULT
    # Lowercase for b/c.
    itu709 = SWS_CS_ITU709
    fcc = SWS_CS_FCC
    itu601 = SWS_CS_ITU601
    itu624 = SWS_CS_ITU624
    smpte170m = SWS_CS_SMPTE170M
    smpte240m = SWS_CS_SMPTE240M
    default = SWS_CS_DEFAULT

class ColorRange(IntEnum):
    UNSPECIFIED: "Unspecified" = lib.AVCOL_RANGE_UNSPECIFIED
    MPEG: "MPEG (limited) YUV range, 219*2^(n-8)" = lib.AVCOL_RANGE_MPEG
    JPEG: "JPEG (full) YUV range, 2^n-1" = lib.AVCOL_RANGE_JPEG
    NB: "Not part of ABI" = lib.AVCOL_RANGE_NB


# Mapping from SWS_CS_* (swscale colorspace) to AVColorSpace (frame metadata).
cdef dict _SWS_CS_TO_AVCOL_SPC = {
    SWS_CS_ITU709: lib.AVCOL_SPC_BT709,
    SWS_CS_FCC: lib.AVCOL_SPC_FCC,
    SWS_CS_ITU601: lib.AVCOL_SPC_SMPTE170M,
    SWS_CS_SMPTE240M: lib.AVCOL_SPC_SMPTE240M,
}


cdef void _set_frame_colorspace(VideoFrame frame, int colorspace, int color_range):
    """Set AVFrame colorspace/range from SWS_CS_* and AVColorRange values."""
    if colorspace in _SWS_CS_TO_AVCOL_SPC:
        frame.ptr.colorspace = <lib.AVColorSpace>_SWS_CS_TO_AVCOL_SPC[colorspace]
    if color_range != lib.AVCOL_RANGE_UNSPECIFIED:
        frame.ptr.color_range = <lib.AVColorRange>color_range


def _resolve_enum_value(value, enum_class, default):
    # Helper function to resolve enum values from different input types.
    if value is None:
        return default
    if isinstance(value, enum_class):
        return value.value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return enum_class[value].value
    raise ValueError(f"Cannot convert {value} to {enum_class.__name__}")


cdef class VideoReformatter:
    """An object for reformatting size and pixel format of :class:`.VideoFrame`.

    It is most efficient to have a reformatter object for each set of parameters
    you will use as calling :meth:`reformat` will reconfigure the internal object.

    """

    def __dealloc__(self):
        with nogil:
            sws_free_context(&self.ptr)

    def reformat(self, VideoFrame frame not None, width=None, height=None,
                 format=None, src_colorspace=None, dst_colorspace=None,
                 interpolation=None, src_color_range=None,
                 dst_color_range=None):
        """Create a new :class:`VideoFrame` with the given width/height/format/colorspace.

        Returns the same frame untouched if nothing needs to be done to it.

        :param int width: New width, or ``None`` for the same width.
        :param int height: New height, or ``None`` for the same height.
        :param format: New format, or ``None`` for the same format.
        :type  format: :class:`.VideoFormat` or ``str``
        :param src_colorspace: Current colorspace, or ``None`` for the frame colorspace.
        :type  src_colorspace: :class:`Colorspace` or ``str``
        :param dst_colorspace: Desired colorspace, or ``None`` for the frame colorspace.
        :type  dst_colorspace: :class:`Colorspace` or ``str``
        :param interpolation: The interpolation method to use, or ``None`` for ``BILINEAR``.
        :type  interpolation: :class:`Interpolation` or ``str``
        :param src_color_range: Current color range, or ``None`` for the ``UNSPECIFIED``.
        :type  src_color_range: :class:`color range` or ``str``
        :param dst_color_range: Desired color range, or ``None`` for the ``UNSPECIFIED``.
        :type  dst_color_range: :class:`color range` or ``str``

        """

        cdef VideoFormat video_format = VideoFormat(format if format is not None else frame.format)

        cdef int c_src_colorspace = _resolve_enum_value(src_colorspace, Colorspace, frame.colorspace)
        cdef int c_dst_colorspace = _resolve_enum_value(dst_colorspace, Colorspace, frame.colorspace)
        cdef int c_interpolation = _resolve_enum_value(interpolation, Interpolation, int(Interpolation.BILINEAR))
        cdef int c_src_color_range = _resolve_enum_value(src_color_range, ColorRange, 0)
        cdef int c_dst_color_range = _resolve_enum_value(dst_color_range, ColorRange, 0)

        return self._reformat(
            frame,
            width or frame.ptr.width,
            height or frame.ptr.height,
            video_format.pix_fmt,
            c_src_colorspace,
            c_dst_colorspace,
            c_interpolation,
            c_src_color_range,
            c_dst_color_range,
        )

    cdef _reformat(self, VideoFrame frame, int width, int height,
                   lib.AVPixelFormat dst_format, int src_colorspace,
                   int dst_colorspace, int interpolation,
                   int src_color_range, int dst_color_range):

        if frame.ptr.format < 0:
            raise ValueError("Frame does not have format set.")

        cdef lib.AVPixelFormat src_format = <lib.AVPixelFormat> frame.ptr.format

        # Shortcut!
        if (
            dst_format == src_format and
            width == frame.ptr.width and
            height == frame.ptr.height and
            dst_colorspace == src_colorspace and
            src_color_range == dst_color_range
        ):
            return frame

        if self.ptr == NULL:
            self.ptr = sws_alloc_context()
            if self.ptr == NULL:
                raise MemoryError("Could not allocate SwsContext")
            self.ptr.threads = 1
        self.ptr.flags = <unsigned int>interpolation

        # Create a new VideoFrame.
        cdef VideoFrame new_frame = alloc_video_frame()
        new_frame._copy_internal_attributes(frame)
        new_frame._init(dst_format, width, height)

        # Set source frame colorspace/range so sws_scale_frame can read it
        cdef lib.AVColorSpace frame_src_colorspace = frame.ptr.colorspace
        cdef lib.AVColorRange frame_src_color_range = frame.ptr.color_range
        _set_frame_colorspace(frame, src_colorspace, src_color_range)
        _set_frame_colorspace(new_frame, dst_colorspace, dst_color_range)

        cdef int ret
        with nogil:
            ret = sws_scale_frame(self.ptr, new_frame.ptr, frame.ptr)

        # Restore source frame colorspace/range to avoid side effects
        frame.ptr.colorspace = frame_src_colorspace
        frame.ptr.color_range = frame_src_color_range

        err_check(ret)

        return new_frame
