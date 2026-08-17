using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.IO;

internal static class IconBuilder
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length < 1) return 2;
        string iconPath = Path.GetFullPath(args[0]);
        string previewPath = args.Length > 1 ? Path.GetFullPath(args[1]) : null;
        using (Bitmap bitmap = new Bitmap(256, 256, PixelFormat.Format32bppArgb))
        using (Graphics graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            graphics.Clear(Color.Transparent);

            PointF[] shield =
            {
                new PointF(128, 16), new PointF(224, 50), new PointF(214, 145),
                new PointF(187, 196), new PointF(128, 238), new PointF(69, 196),
                new PointF(42, 145), new PointF(32, 50)
            };
            using (GraphicsPath path = new GraphicsPath())
            {
                path.AddClosedCurve(shield, 0.16F);
                using (LinearGradientBrush fill = new LinearGradientBrush(new Rectangle(22, 12, 212, 230), Color.FromArgb(44, 129, 219), Color.FromArgb(18, 51, 91), 90F))
                    graphics.FillPath(fill, path);
                using (Pen border = new Pen(Color.FromArgb(220, 235, 249), 8F)) graphics.DrawPath(border, path);
            }

            using (Pen shackle = new Pen(Color.White, 18F))
            {
                shackle.StartCap = LineCap.Round;
                shackle.EndCap = LineCap.Round;
                graphics.DrawArc(shackle, 83, 74, 90, 88, 190, 160);
            }
            using (SolidBrush lockBody = new SolidBrush(Color.White)) graphics.FillRoundedRectangle(lockBody, new RectangleF(70, 118, 116, 82), 16F);
            using (SolidBrush keyhole = new SolidBrush(Color.FromArgb(25, 76, 130)))
            {
                graphics.FillEllipse(keyhole, 116, 143, 24, 24);
                graphics.FillRectangle(keyhole, 123, 158, 10, 21);
            }

            using (MemoryStream png = new MemoryStream())
            {
                bitmap.Save(png, ImageFormat.Png);
                byte[] bytes = png.ToArray();
                using (FileStream output = new FileStream(iconPath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (BinaryWriter writer = new BinaryWriter(output))
                {
                    writer.Write((ushort)0);
                    writer.Write((ushort)1);
                    writer.Write((ushort)1);
                    writer.Write((byte)0);
                    writer.Write((byte)0);
                    writer.Write((byte)0);
                    writer.Write((byte)0);
                    writer.Write((ushort)1);
                    writer.Write((ushort)32);
                    writer.Write(bytes.Length);
                    writer.Write(22);
                    writer.Write(bytes);
                }
            }
            if (!string.IsNullOrEmpty(previewPath)) bitmap.Save(previewPath, ImageFormat.Png);
        }
        return 0;
    }

    private static void FillRoundedRectangle(this Graphics graphics, Brush brush, RectangleF rectangle, float radius)
    {
        float diameter = radius * 2F;
        using (GraphicsPath path = new GraphicsPath())
        {
            path.AddArc(rectangle.Left, rectangle.Top, diameter, diameter, 180, 90);
            path.AddArc(rectangle.Right - diameter, rectangle.Top, diameter, diameter, 270, 90);
            path.AddArc(rectangle.Right - diameter, rectangle.Bottom - diameter, diameter, diameter, 0, 90);
            path.AddArc(rectangle.Left, rectangle.Bottom - diameter, diameter, diameter, 90, 90);
            path.CloseFigure();
            graphics.FillPath(brush, path);
        }
    }
}
