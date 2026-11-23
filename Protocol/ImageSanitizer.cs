using System;
using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace VeilDesktop.Protocol;

public static class ImageSanitizer
{
    public static bool IsSupportedImage(string filePath)
    {
        string ext = Path.GetExtension(filePath).ToLowerInvariant();
        return ext is ".jpg" or ".jpeg" or ".png" or ".bmp" or ".tif" or ".tiff";
    }

    public static byte[] StripMetadata(string filePath, out bool wasStripped)
    {
        byte[] raw = File.ReadAllBytes(filePath);
        if (!IsSupportedImage(filePath))
        {
            wasStripped = false;
            return raw;
        }

        try
        {
            using var input = new MemoryStream(raw);
            var decoder = BitmapDecoder.Create(input, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count == 0)
            {
                wasStripped = false;
                return raw;
            }

            BitmapFrame frame = decoder.Frames[0];
            BitmapSource oriented = ApplyExifOrientation(frame);
            var cleanBitmap = new WriteableBitmap(oriented);
            BitmapFrame cleanFrame = BitmapFrame.Create(cleanBitmap);

            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            BitmapEncoder encoder = ext switch
            {
                ".jpg" or ".jpeg" => new JpegBitmapEncoder { QualityLevel = 92 },
                ".bmp" => new BmpBitmapEncoder(),
                ".tif" or ".tiff" => new TiffBitmapEncoder(),
                _ => new PngBitmapEncoder(),
            };

            encoder.Frames.Add(cleanFrame);
            using var output = new MemoryStream();
            encoder.Save(output);
            wasStripped = true;
            return output.ToArray();
        }
        catch
        {
            wasStripped = false;
            return raw;
        }
    }

    private static BitmapSource ApplyExifOrientation(BitmapFrame frame)
    {
        try
        {
            if (frame.Metadata is BitmapMetadata meta && meta.ContainsQuery("System.Photo.Orientation"))
            {
                object? val = meta.GetQuery("System.Photo.Orientation");
                if (val is ushort orient)
                {
                    double angle = orient switch
                    {
                        6 => 90,
                        3 => 180,
                        8 => 270,
                        _ => 0,
                    };
                    if (angle != 0)
                        return new TransformedBitmap(frame, new RotateTransform(angle));
                }
            }
        }
        catch { }
        return frame;
    }
}
