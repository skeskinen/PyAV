cimport libav as lib
from libc.stdint cimport uint8_t

from av.error cimport err_check
from av.video.format cimport VideoFormat, get_pix_fmt
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
    LANCZOS: "3-tap sinc/sinc" = SWS_LANCZOS
    SPLINE: "Cubic Keys spline" = SWS_SPLINE


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


cdef void _set_frame_colorspace(lib.AVFrame *frame, int colorspace, int color_range):
    """Set AVFrame colorspace/range from SWS_CS_* and AVColorRange values."""
    if color_range != lib.AVCOL_RANGE_UNSPECIFIED:
        frame.color_range = <lib.AVColorRange>color_range
    # Mapping from SWS_CS_* (swscale colorspace) to AVColorSpace (frame metadata).
    # Note: SWS_CS_ITU601, SWS_CS_ITU624, SWS_CS_SMPTE170M, and SWS_CS_DEFAULT all have
    # the same value (5), so we map 5 -> AVCOL_SPC_SMPTE170M as the most common case.
    # SWS_CS_DEFAULT is handled specially by not setting frame metadata.
    if colorspace == SWS_CS_ITU709:
        frame.colorspace = lib.AVCOL_SPC_BT709
    elif colorspace == SWS_CS_FCC:
        frame.colorspace = lib.AVCOL_SPC_FCC
    elif colorspace == SWS_CS_ITU601:
        frame.colorspace = lib.AVCOL_SPC_SMPTE170M
    elif colorspace == SWS_CS_SMPTE240M:
        frame.colorspace = lib.AVCOL_SPC_SMPTE240M


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


cdef lib.AVPixelFormat _resolve_format(object format, lib.AVPixelFormat default):
    if format is None:
        return default
    if isinstance(format, VideoFormat):
        return (<VideoFormat>format).pix_fmt
    return get_pix_fmt(format)


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
                 dst_color_range=None, threads=None):
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

        cdef lib.AVPixelFormat c_dst_format = _resolve_format(format, frame.format.pix_fmt)
        cdef int c_src_colorspace = _resolve_enum_value(src_colorspace, Colorspace, frame.ptr.colorspace)
        cdef int c_dst_colorspace = _resolve_enum_value(dst_colorspace, Colorspace, frame.ptr.colorspace)
        cdef int c_interpolation = _resolve_enum_value(interpolation, Interpolation, SWS_BILINEAR)
        cdef int c_src_color_range = _resolve_enum_value(src_color_range, ColorRange, 0)
        cdef int c_dst_color_range = _resolve_enum_value(dst_color_range, ColorRange, 0)
        cdef int c_threads = threads if threads is not None else 0
        cdef int c_width = width if width is not None else frame.ptr.width
        cdef int c_height = height if height is not None else frame.ptr.height

        return self._reformat(
            frame,
            c_width,
            c_height,
            c_dst_format,
            c_src_colorspace,
            c_dst_colorspace,
            c_interpolation,
            c_src_color_range,
            c_dst_color_range,
            c_threads,
        )

    cdef _reformat(self, VideoFrame frame, int width, int height,
                   lib.AVPixelFormat dst_format, int src_colorspace,
                   int dst_colorspace, int interpolation,
                   int src_color_range, int dst_color_range,
                   int threads):

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
        self.ptr.threads = threads
        self.ptr.flags = <unsigned int>interpolation

        # Create a new VideoFrame.
        cdef VideoFrame new_frame = alloc_video_frame()
        new_frame._copy_internal_attributes(frame)
        new_frame._init(dst_format, width, height)

        # Set source frame colorspace/range so sws_scale_frame can read it
        cdef lib.AVColorSpace frame_src_colorspace = frame.ptr.colorspace
        cdef lib.AVColorRange frame_src_color_range = frame.ptr.color_range
        _set_frame_colorspace(frame.ptr, src_colorspace, src_color_range)
        _set_frame_colorspace(new_frame.ptr, dst_colorspace, dst_color_range)

        cdef int ret
        with nogil:
            ret = sws_scale_frame(self.ptr, new_frame.ptr, frame.ptr)

        # Restore source frame colorspace/range to avoid side effects
        frame.ptr.colorspace = frame_src_colorspace
        frame.ptr.color_range = frame_src_color_range

        err_check(ret)

        return new_frame
