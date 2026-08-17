using System.Drawing;
using System.Windows.Forms;

namespace CodexGuard.App
{
    internal static class UiStyles
    {
        public static readonly Color Navy = Color.FromArgb(21, 37, 61);
        public static readonly Color Blue = Color.FromArgb(38, 113, 190);
        public static readonly Color PaleBlue = Color.FromArgb(236, 244, 252);
        public static readonly Color Green = Color.FromArgb(31, 132, 91);
        public static readonly Color Red = Color.FromArgb(190, 57, 57);
        public static readonly Color Amber = Color.FromArgb(176, 111, 23);
        public static readonly Color Muted = Color.FromArgb(92, 104, 120);

        public static Font TitleFont()
        {
            return new Font("Microsoft YaHei UI", 20F, FontStyle.Bold, GraphicsUnit.Point);
        }

        public static Font HeadingFont()
        {
            return new Font("Microsoft YaHei UI", 10.5F, FontStyle.Bold, GraphicsUnit.Point);
        }

        public static Font BodyFont()
        {
            return new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
        }

        public static Button PrimaryButton(string text)
        {
            return StyledButton(text, Blue, Color.White, 0, Blue);
        }

        public static Button SecondaryButton(string text)
        {
            return StyledButton(text, Color.White, Navy, 1, Color.FromArgb(180, 190, 202));
        }

        private static Button StyledButton(string text, Color enabledBackColor, Color enabledForeColor, int borderSize, Color borderColor)
        {
            Button button = new Button();
            button.Text = text;
            button.AutoSize = true;
            button.MinimumSize = new Size(112, 34);
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderSize = borderSize;
            button.FlatAppearance.BorderColor = borderColor;
            button.BackColor = enabledBackColor;
            button.ForeColor = enabledForeColor;
            button.Font = BodyFont();
            button.Padding = new Padding(10, 2, 10, 2);
            button.EnabledChanged += delegate
            {
                button.BackColor = button.Enabled ? enabledBackColor : Color.FromArgb(224, 228, 234);
                button.ForeColor = button.Enabled ? enabledForeColor : Color.FromArgb(130, 138, 148);
            };
            return button;
        }

        public static Label Label(string text, bool heading)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Font = heading ? HeadingFont() : BodyFont(),
                ForeColor = heading ? Navy : Muted,
                Margin = new Padding(3, 5, 3, 5)
            };
        }

        public static void PrepareForm(Form form)
        {
            form.Font = BodyFont();
            form.BackColor = Color.White;
            form.StartPosition = FormStartPosition.CenterScreen;
            form.AutoScaleMode = AutoScaleMode.Dpi;
        }
    }
}
