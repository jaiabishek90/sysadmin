<#
================================================================================
 Sys@dmin - Windows Endpoint Diagnostics Console  (v4)
 --------------------------------------------------------------------------
 Tabs : Dashboard | Event Analysis | Resolutions | Network | Certificates |
        Intune / MDM | Group Policy | System Health | Actions and Report

 v4 :
   * RESPONSIVE LAYOUT - every data tab uses star-sized Grid rows/columns with
     draggable GridSplitter bars. Cards resize with the window and can be
     dragged larger or smaller. No fixed pixel heights on data grids.
   * Engine type-coercion fix (see DiagEngine.ps1 header) - Firewall, GPO,
     Intune and DNS collectors no longer empty themselves.
   * Intune: platform PowerShell scripts + Remediations grids, decoded Win32
     enforcement state, collector notes surfaced.
   * PS2EXE-safe path resolution.

 Run  : right-click Launch-EndpointDiagX.cmd  ->  Run as administrator
================================================================================
#>
[CmdletBinding()]
param([switch]$NoElevate, [switch]$SkipAutoScan)

# =============================================================================
#  Location resolution - works as .ps1 AND as a PS2EXE-compiled .exe
# =============================================================================
#  In a compiled executable $PSScriptRoot and $PSCommandPath are EMPTY, because
#  no .ps1 file exists at runtime. Resolve from the process image instead.
# =============================================================================
$script:IsCompiled = $false
$script:AppRoot    = $PSScriptRoot
$script:SelfPath   = $PSCommandPath

if ([string]::IsNullOrEmpty($script:AppRoot)) {
    $script:IsCompiled = $true
    try {
        $script:SelfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
        $script:AppRoot  = Split-Path -Parent $script:SelfPath
    }
    catch {
        try {
            $script:SelfPath = Convert-Path ([Environment]::GetCommandLineArgs()[0])
            $script:AppRoot  = Split-Path -Parent $script:SelfPath
        }
        catch { $script:AppRoot = (Get-Location).Path }
    }
}
if ([string]::IsNullOrEmpty($script:AppRoot)) { $script:AppRoot = (Get-Location).Path }

# Relaunch for STA only applies to the .ps1 path - PS2EXE is built -STA already.
if (-not $script:IsCompiled -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',"`"$PSCommandPath`"") -Verb Open
    return
}

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$script:IsElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $script:IsElevated -and -not $NoElevate) {
    try {
        if ($script:IsCompiled) { Start-Process -FilePath $script:SelfPath -Verb RunAs }
        else { Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-STA','-File',"`"$PSCommandPath`"") }
        return
    } catch { }
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms, System.Drawing, System.Xml

$script:EnginePath = Join-Path $script:AppRoot 'DiagEngine.ps1'
if (-not (Test-Path $script:EnginePath)) {
    [Windows.Forms.MessageBox]::Show(
        ("DiagEngine.ps1 was not found beside the application.`r`n`r`n" +
         "Looked in : $($script:AppRoot)`r`n" +
         "Running as: $(if($script:IsCompiled){'compiled executable'}else{'PowerShell script'})`r`n`r`n" +
         "Keep DiagEngine.ps1 and KnowledgeBase.json in the same folder."),
        'Sys@dmin', 'OK', 'Error') | Out-Null
    return
}
. $script:EnginePath

# ---- branding + device identity -------------------------------------------
$script:AppName      = 'Sys@dmin'
$script:DeviceSerial = ''

function Get-DxQuickSerial {
    # Fast synchronous serial read so the title is correct before any scan runs.
    # VMs and some OEMs return placeholder junk - treat those as "no serial".
    $sn = ''
    try { $sn = "$((Get-CimInstance Win32_BIOS -ErrorAction Stop).SerialNumber)".Trim() } catch { }
    if (-not $sn) {
        try { $sn = "$((Get-CimInstance Win32_SystemEnclosure -ErrorAction Stop).SerialNumber)".Trim() } catch { }
    }
    if ($sn -match '^(To be filled by O\.E\.M\.?|System Serial Number|Default string|None|Not Specified|0+)$') { $sn = '' }
    return $sn
}

function Set-DxWindowTitle {
    param([string]$Serial = '')
    try {
        if ($Serial) { $script:DeviceSerial = $Serial.Trim() }
        $t = "$script:AppName  -  $env:COMPUTERNAME"
        if ($script:DeviceSerial) { $t = "$t  -  S/N $($script:DeviceSerial)" }
        $window.Title = $t
        if ($UI.lblSerial) {
            if ($script:DeviceSerial) { $UI.lblSerial.Text = "S/N $($script:DeviceSerial)" }
            else { $UI.lblSerial.Text = 'S/N unavailable' }
        }
    } catch { }
}

$script:Data = @{
    Snapshot=$null; Events=@(); EventStats=$null; EventSummary=@()
    Intune=$null; IntuneLogs=@(); Gpo=$null; Policy=$null; SysDiag=$null; Health=$null
    Adv=$null; IntuneDeep=$null
    Certs=@(); CertSummary=$null; CertFindings=@()
    Firewall=$null; Dns=$null; Adapters=@()
}
$script:Jobs = New-Object System.Collections.ArrayList

# =============================================================================
#  XAML  - part 1 : resources, header, toolbar, Dashboard, Events, Resolutions
# =============================================================================
$xamlText = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Sys@dmin"
        Height="980" Width="1660" MinHeight="600" MinWidth="1100"
        WindowStartupLocation="CenterScreen"
        Background="{DynamicResource DxWindowBg}" FontFamily="Segoe UI" FontSize="12">
  <Window.Resources>
    <!-- ================= THEME BRUSHES =================================
         Values are swapped at runtime by Set-DxTheme. Anything that should
         follow the theme references these with {DynamicResource ...}.
         Do NOT convert these to StaticResource - the live swap depends on
         dynamic lookup.

         Every key here MUST also exist in both halves of $script:DxPalette.
         An undefined key does not throw - the control silently keeps an
         unset brush and stops following the theme, which is exactly how
         DxFieldBg, DxIconFg and DxTabStripBg spent v4 inside this comment.
         ================================================================= -->

    <!-- surfaces -->
        <SolidColorBrush x:Key="DxBtnGhostBg" Color="#FF6E5AC0"/>
    <SolidColorBrush x:Key="DxBtnChipBg" Color="#FF63509E"/>
    <SolidColorBrush x:Key="DxBtnGhostBorder" Color="#FF9585D8"/>
<SolidColorBrush x:Key="DxWindowBg"        Color="#FFEDF1F7"/>
    <SolidColorBrush x:Key="DxCardBg"          Color="#FFFFFFFF"/>
    <SolidColorBrush x:Key="DxCardBorder"      Color="#FFDCE3ED"/>
    <SolidColorBrush x:Key="DxFieldBg"         Color="#FFFFFFFF"/>
    <SolidColorBrush x:Key="DxTabStripBg"      Color="#FFF7F9FC"/>
    <SolidColorBrush x:Key="DxSubtle"          Color="#FFF6F8FC"/>
    <SolidColorBrush x:Key="DxTrack"           Color="#FFE7ECF3"/>
    <SolidColorBrush x:Key="DxNavBg"           Color="#FFFFFFFF"/>
    <SolidColorBrush x:Key="DxNavEdge"         Color="#FFDCE3ED"/>

    <!-- ink -->
    <SolidColorBrush x:Key="DxInk"             Color="#FF10182A"/>
    <SolidColorBrush x:Key="DxMuted"           Color="#FF5C6979"/>
    <SolidColorBrush x:Key="DxFaint"           Color="#FF8B98A9"/>
    <SolidColorBrush x:Key="DxHeaderFg"        Color="#FF44526A"/>
    <SolidColorBrush x:Key="DxIconFg"          Color="#FF5B6878"/>

    <!-- accent -->
    <SolidColorBrush x:Key="DxAccent"          Color="#FF4F46E5"/>
    <SolidColorBrush x:Key="DxAccentHi"        Color="#FF6366F1"/>
    <SolidColorBrush x:Key="DxAccentPress"     Color="#FF4338CA"/>
    <SolidColorBrush x:Key="DxOnAccent"        Color="#FFFFFFFF"/>
    <SolidColorBrush x:Key="DxRowHover"        Color="#FFE7ECFB"/>
    <SolidColorBrush x:Key="DxAccentSoftFg"    Color="#FF3730A3"/>
    <SolidColorBrush x:Key="DxDisabled"        Color="#FFC7D0DC"/>

    <!-- action buttons -->
    <SolidColorBrush x:Key="DxGhost"           Color="#FF475569"/>
    <SolidColorBrush x:Key="DxOk"              Color="#FF059669"/>
    <SolidColorBrush x:Key="DxWarn"            Color="#FFD97706"/>
    <SolidColorBrush x:Key="DxDanger"          Color="#FFDC2626"/>
    <SolidColorBrush x:Key="DxChip"            Color="#FF334155"/>

    <!-- spotlight: the one inverted card per tab, carrying the number that
         matters. In Dark it deliberately goes LIGHTER than DxCardBg - an
         inverted surface has to invert its direction too, or it reads as a
         hole punched in the page instead of a raised panel. -->
    <SolidColorBrush x:Key="DxSpotBg"          Color="#FF131C2E"/>
    <SolidColorBrush x:Key="DxSpotEdge"        Color="#FF131C2E"/>
    <SolidColorBrush x:Key="DxSpotFg"          Color="#FFF2F5FA"/>
    <SolidColorBrush x:Key="DxSpotMuted"       Color="#FF93A2B8"/>

    <!-- console / status bar / header -->
    <SolidColorBrush x:Key="DxConsoleBg"       Color="#FF0C1320"/>
    <SolidColorBrush x:Key="DxConsoleFg"       Color="#FF7CE7A8"/>
    <SolidColorBrush x:Key="DxConsoleEdge"     Color="#FF0C1320"/>
    <SolidColorBrush x:Key="DxStatusBg"        Color="#FF131C2E"/>
    <SolidColorBrush x:Key="DxStatusFg"        Color="#FFC6D0DF"/>
    <SolidColorBrush x:Key="DxHeadFgSoft"      Color="#FFA9B2FA"/>
    <SolidColorBrush x:Key="DxHeadChipBg"      Color="#22FFFFFF"/>
    <SolidColorBrush x:Key="DxBadgeOk"         Color="#3310B981"/>
    <SolidColorBrush x:Key="DxAccentSoftBg"    Color="#FFEEF2FF"/>
    <SolidColorBrush x:Key="DxAccentSoftEdge"  Color="#FFC7D2FE"/>
    <SolidColorBrush x:Key="DxSevCritBg"       Color="#FFFEE2E2"/>
    <SolidColorBrush x:Key="DxSevCritFg"       Color="#FF7F1D1D"/>
    <SolidColorBrush x:Key="DxSevCritEdge"     Color="#FFFECACA"/>
    <SolidColorBrush x:Key="DxSevErrBg"        Color="#FFFEF2F2"/>
    <SolidColorBrush x:Key="DxSevErrFg"        Color="#FFB91C1C"/>
    <SolidColorBrush x:Key="DxSevWarnBg"       Color="#FFFFFBEB"/>
    <SolidColorBrush x:Key="DxSevWarnFg"       Color="#FF92400E"/>
    <SolidColorBrush x:Key="DxSevWarnEdge"     Color="#FFFDE68A"/>
    <SolidColorBrush x:Key="DxSevWarnBg2"      Color="#FFFEF3C7"/>
    <SolidColorBrush x:Key="DxSevInfoBg"       Color="#FFF0F9FF"/>
    <SolidColorBrush x:Key="DxSevInfoFg"       Color="#FF1D4ED8"/>
    <SolidColorBrush x:Key="DxSevInfoEdge"     Color="#FFBFDBFE"/>
    <SolidColorBrush x:Key="DxSevInfoBg2"      Color="#FFDBEAFE"/>
    <SolidColorBrush x:Key="DxSevInfoEdge2"    Color="#FFBAE6FD"/>
    <SolidColorBrush x:Key="DxSevOkBg"         Color="#FFF0FDF4"/>
    <SolidColorBrush x:Key="DxSevOkFg"         Color="#FF166534"/>
    <SolidColorBrush x:Key="DxSevOkEdge"       Color="#FFBBF7D0"/>
    <SolidColorBrush x:Key="DxSevOkBg2"        Color="#FFDCFCE7"/>
    <SolidColorBrush x:Key="DxSevOrangeBg"     Color="#FFFFEDD5"/>
    <SolidColorBrush x:Key="DxSevOrangeFg"     Color="#FF9A3412"/>
    <SolidColorBrush x:Key="DxSevOrangeEdge"   Color="#FFFED7AA"/>


    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="10"/>
      <Setter Property="Padding" Value="15,13"/>
      <Setter Property="Margin" Value="5"/>
      <Setter Property="SnapsToDevicePixels" Value="True"/>
    </Style>
    <Style x:Key="CardTitle" TargetType="TextBlock">
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Foreground" Value="{DynamicResource DxMuted}"/>
      <Setter Property="Margin" Value="0,0,0,8"/>
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
    </Style>
    <Style x:Key="KpiLabel" TargetType="TextBlock">
      <Setter Property="FontSize" Value="9.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Opacity" Value="0.82"/>
      <Setter Property="TextTrimming" Value="CharacterEllipsis"/>
      <Setter Property="Margin" Value="0,0,0,2"/>
    </Style>
    <!-- Tabular figures: KPI numbers are rewritten live during a scan, and
         proportional digits make the whole row twitch on every update. -->
    <Style x:Key="KpiValue" TargetType="TextBlock">
      <Setter Property="FontSize" Value="30"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Typography.NumeralAlignment" Value="Tabular"/>
      <Setter Property="Margin" Value="0,-2,0,0"/>
    </Style>

    <Style TargetType="GridSplitter">
      <Setter Property="Background" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="ShowsPreview" Value="True"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="GridSplitter">
            <Border x:Name="sp" Background="Transparent" Padding="0">
              <Border x:Name="grip" Background="{DynamicResource DxCardBorder}" CornerRadius="3" Margin="3"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="grip" Property="Background" Value="{DynamicResource DxAccentHi}"/>
              </Trigger>
              <Trigger Property="IsDragging" Value="True">
                <Setter TargetName="grip" Property="Background" Value="{DynamicResource DxAccentPress}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="HSplit" TargetType="GridSplitter">
      <Setter Property="Height" Value="9"/>
      <Setter Property="HorizontalAlignment" Value="Stretch"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="ResizeBehavior" Value="PreviousAndNext"/>
      <Setter Property="ResizeDirection" Value="Rows"/>
      <Setter Property="Cursor" Value="SizeNS"/>
      <Setter Property="Background" Value="Transparent"/>
    </Style>
    <Style x:Key="VSplit" TargetType="GridSplitter">
      <Setter Property="Width" Value="9"/>
      <Setter Property="VerticalAlignment" Value="Stretch"/>
      <Setter Property="HorizontalAlignment" Value="Center"/>
      <Setter Property="ResizeBehavior" Value="PreviousAndNext"/>
      <Setter Property="ResizeDirection" Value="Columns"/>
      <Setter Property="Cursor" Value="SizeWE"/>
      <Setter Property="Background" Value="Transparent"/>
    </Style>

    <Style TargetType="Button">
      <Setter Property="Padding" Value="13,7"/>
      <Setter Property="Margin" Value="0,0,8,6"/>
      <Setter Property="Background" Value="{DynamicResource DxAccent}"/>
      <Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="HorizontalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="bd" Background="{TemplateBinding Background}" CornerRadius="6" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="{TemplateBinding HorizontalContentAlignment}" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.86"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="bd" Property="Opacity" Value="0.70"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="bd" Property="Background" Value="{DynamicResource DxDisabled}"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="BtnGhost" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{DynamicResource DxBtnGhostBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxBtnGhostBorder}"/>
      <Setter Property="BorderThickness" Value="1"/></Style>
    <Style x:Key="BtnOk" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="Background" Value="{DynamicResource DxOk}"/></Style>
    <Style x:Key="BtnWarn" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="Background" Value="{DynamicResource DxWarn}"/></Style>
    <Style x:Key="BtnDanger" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}"><Setter Property="Background" Value="{DynamicResource DxDanger}"/></Style>
    <Style x:Key="BtnChip" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="{DynamicResource DxBtnChipBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxBtnGhostBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Padding" Value="10,5"/>
      <Setter Property="Margin" Value="0,0,6,0"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="FontWeight" Value="Normal"/>
    </Style>
    <Style x:Key="BtnMini" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Padding" Value="9,4"/>
      <Setter Property="Margin" Value="0,0,5,0"/>
      <Setter Property="FontSize" Value="10.5"/>
    </Style>
    <!-- Vector geometry, deliberately NOT an icon font - Segoe MDL2 glyphs
         render as empty boxes on some builds. Fill follows the theme. -->
    <Style x:Key="DxIcon" TargetType="Path">
      <Setter Property="Width" Value="15"/>
      <Setter Property="Height" Value="15"/>
      <Setter Property="Stretch" Value="Uniform"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Margin" Value="0,0,7,0"/>
      <Setter Property="Fill" Value="{DynamicResource DxIconFg}"/>
    </Style>


    <!-- ================= LEFT SIDEBAR NAVIGATION =======================
         KEYED deliberately. An implicit TabItem style here would cascade
         into every nested TabControl and rebuild all 33 sub-tabs as rail
         items. Only the eight top-level TabItems opt in.
         ================================================================= -->
    <Style x:Key="SideNav" TargetType="TabControl">
      <Setter Property="TabStripPlacement" Value="Left"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabControl">
            <Grid>
              <Grid.ColumnDefinitions>
                <!-- Auto, so collapsing the labels shrinks the rail to an
                     icon column with no second measurement pass. -->
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>

              <Border Grid.Column="0"
                      Background="{DynamicResource DxNavBg}"
                      BorderBrush="{DynamicResource DxNavEdge}"
                      BorderThickness="1" CornerRadius="14"
                      Margin="10,8,7,8" Padding="8,10"
                      SnapsToDevicePixels="True">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                  <StackPanel IsItemsHost="True"/>
                </ScrollViewer>
              </Border>

              <Border Grid.Column="1"
                      Background="{DynamicResource DxCardBg}"
                      BorderBrush="{DynamicResource DxCardBorder}"
                      BorderThickness="1" CornerRadius="14"
                      Margin="0,8,10,8" SnapsToDevicePixels="True">
                <ContentPresenter ContentSource="SelectedContent" Margin="2"/>
              </Border>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style x:Key="SideNavItem" TargetType="TabItem">
      <Setter Property="Foreground" Value="{DynamicResource DxMuted}"/>
      <Setter Property="FontSize" Value="12.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Grid Margin="0,1">
              <Border x:Name="bd" Background="Transparent" CornerRadius="9"
                      Padding="11,9" MinWidth="40" SnapsToDevicePixels="True">
                <ContentPresenter ContentSource="Header" HorizontalAlignment="Left" VerticalAlignment="Center"/>
              </Border>
              <!-- active marker: a left bar rather than an underline, which is
                   what makes a vertical rail read as a rail -->
              <Border x:Name="bar" Width="3" HorizontalAlignment="Left"
                      CornerRadius="2" Margin="0,8" Background="Transparent"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource DxSubtle}"/>
                <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource DxAccentSoftBg}"/>
                <Setter TargetName="bar" Property="Background" Value="{DynamicResource DxAccent}"/>
                <Setter Property="Foreground" Value="{DynamicResource DxAccentSoftFg}"/>
              </Trigger>
              <Trigger Property="IsKeyboardFocusWithin" Value="True">
                <Setter TargetName="bd" Property="BorderBrush" Value="{DynamicResource DxAccent}"/>
                <Setter TargetName="bd" Property="BorderThickness" Value="1"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <Style TargetType="TabItem">
      <Setter Property="Foreground" Value="{DynamicResource DxMuted}"/>
      <Setter Property="FontSize" Value="12.5"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TabItem">
            <Border x:Name="bd" Background="Transparent" BorderBrush="Transparent" BorderThickness="0,0,0,2" Padding="16,10,16,8">
              <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True">
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource DxSubtle}"/>
                <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
              </Trigger>
              <Trigger Property="IsSelected" Value="True">
                <Setter TargetName="bd" Property="BorderBrush" Value="{DynamicResource DxAccent}"/>
                <Setter TargetName="bd" Property="Background" Value="{DynamicResource DxAccentSoftBg}"/>
                <Setter Property="Foreground" Value="{DynamicResource DxAccentSoftFg}"/>
              </Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>

    <!-- WPF paints DataGrid/ListBox backgrounds from a SYSTEM brush.
         RowBackground only paints ROWS, so without these the empty area
         under the last row stays white on a dark theme. -->
    <Style TargetType="DataGridCell">
      <Setter Property="Foreground" Value="{Binding Foreground, RelativeSource={RelativeSource AncestorType=DataGridRow}}"/>
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="BorderBrush" Value="Transparent"/>
      <Setter Property="BorderThickness" Value="0"/>
      <Setter Property="Padding" Value="4,0"/>
      <Style.Triggers>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="Transparent"/>
          <Setter Property="BorderBrush" Value="Transparent"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="ListBox">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxCardBorder}"/>
    </Style>
    <Style TargetType="ListBoxItem">
      <Setter Property="Background" Value="Transparent"/>
      <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Setter Property="Padding" Value="7,4"/>
    </Style>
    <Style TargetType="ScrollViewer">
      <Setter Property="Background" Value="Transparent"/>
    </Style>
    <Style TargetType="ItemsControl">
      <Setter Property="Background" Value="Transparent"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Background" Value="{DynamicResource DxFieldBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="CaretBrush" Value="{DynamicResource DxInk}"/>
      <Setter Property="SelectionBrush" Value="{DynamicResource DxAccent}"/>
      <Setter Property="Padding" Value="6,4"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Style.Triggers>
        <Trigger Property="IsKeyboardFocusWithin" Value="True">
          <Setter Property="BorderBrush" Value="{DynamicResource DxAccent}"/>
        </Trigger>
      </Style.Triggers>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
    </Style>
    <Style TargetType="TabControl">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxCardBorder}"/>
    </Style>

    <Style TargetType="DataGrid">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Setter Property="HorizontalGridLinesBrush" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="VerticalGridLinesBrush" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="AutoGenerateColumns" Value="False"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="GridLinesVisibility" Value="None"/>
      <Setter Property="RowBackground" Value="{DynamicResource DxCardBg}"/>
      <Setter Property="HeadersVisibility" Value="Column"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CanUserResizeRows" Value="False"/>
      <Setter Property="SelectionMode" Value="Single"/>
      <Setter Property="FontSize" Value="11.5"/>
      <Setter Property="RowHeight" Value="25"/>
      <Setter Property="MinHeight" Value="60"/>
      <Setter Property="EnableRowVirtualization" Value="True"/>
      <Setter Property="EnableColumnVirtualization" Value="False"/>
      <Setter Property="ScrollViewer.CanContentScroll" Value="True"/>
      <Setter Property="HorizontalScrollBarVisibility" Value="Auto"/>
      <Setter Property="VerticalScrollBarVisibility" Value="Auto"/>
    </Style>
        <!-- DxImplicitRowStyle
         IMPLICIT (unkeyed) row style. Without this, a DataGrid that does not
         set RowStyle uses the WPF default, whose selected-row foreground is
         SystemColors.HighlightTextBrush (white) - invisible on a light theme.
         Grids with an explicit RowStyle are unaffected; explicit always wins. -->
    <Style TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/>
      <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <Trigger Property="IsMouseOver" Value="True">
          <Setter Property="Background" Value="{DynamicResource DxRowHover}"/>
          <Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
        </Trigger>
        <Trigger Property="IsSelected" Value="True">
          <Setter Property="Background" Value="{DynamicResource DxAccent}"/>
          <Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/>
          <Setter Property="FontWeight" Value="SemiBold"/>
        </Trigger>
      </Style.Triggers>
    </Style>
<Style TargetType="DataGridColumnHeader">
      <Setter Property="Background" Value="{DynamicResource DxSubtle}"/>
      <Setter Property="Foreground" Value="{DynamicResource DxHeaderFg}"/>
      <Setter Property="FontWeight" Value="SemiBold"/>
      <Setter Property="FontSize" Value="10.5"/>
      <Setter Property="Padding" Value="9,8"/>
      <Setter Property="BorderBrush" Value="{DynamicResource DxCardBorder}"/>
      <Setter Property="BorderThickness" Value="0,0,0,1"/>
      <Setter Property="HorizontalContentAlignment" Value="Left"/>
    </Style>

    <Style x:Key="RowLevel" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Level}" Value="Critical"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Level}" Value="Error"><Setter Property="Background" Value="{DynamicResource DxSevErrBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevErrFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding Level}" Value="Warning"><Setter Property="Background" Value="{DynamicResource DxSevWarnBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevWarnFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding Level}" Value="Information"><Setter Property="Background" Value="{DynamicResource DxSevInfoBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevInfoFg}"/></DataTrigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource DxRowHover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowSeverity" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Severity}" Value="Critical"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Severity}" Value="Error"><Setter Property="Background" Value="{DynamicResource DxSevErrBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevErrFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Severity}" Value="Warning"><Setter Property="Background" Value="{DynamicResource DxSevWarnBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevWarnFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding Severity}" Value="Info"><Setter Property="Background" Value="{DynamicResource DxSevInfoBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevInfoFg}"/></DataTrigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource DxRowHover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowCert" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Expired"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Critical"><Setter Property="Background" Value="{DynamicResource DxSevOrangeBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOrangeFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Warning"><Setter Property="Background" Value="{DynamicResource DxSevWarnBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevWarnFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding Status}" Value="Valid"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowBool" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Reachable}" Value="True"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding Reachable}" Value="False"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowFwProfile" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Enabled"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/><Setter Property="FontWeight" Value="Normal"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowFwRule" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Action}" Value="Block"><Setter Property="Background" Value="{DynamicResource DxSevErrBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevErrFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding Direction}" Value="Inbound"><Setter Property="Background" Value="{DynamicResource DxSevInfoBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevInfoFg}"/></DataTrigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource DxRowHover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowFwLog" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Action}" Value="DROP"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Action}" Value="ALLOW"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowResolved" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Resolved}" Value="True"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowScript" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding State}" Value="Success"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding State}" Value="Failed"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding State}" Value="Unknown"><Setter Property="Background" Value="{DynamicResource DxSevWarnBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevWarnFg}"/></DataTrigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource DxRowHover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowPort" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Open}" Value="True"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding Open}" Value="False"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowHop" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding State}" Value="Destination"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/><Setter Property="FontWeight" Value="SemiBold"/></DataTrigger>
        <DataTrigger Binding="{Binding State}" Value="No reply"><Setter Property="Background" Value="{DynamicResource DxSevWarnBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevWarnFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding State}" Value="Slow"><Setter Property="Background" Value="{DynamicResource DxSevOrangeBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOrangeFg}"/></DataTrigger>
        <DataTrigger Binding="{Binding State}" Value="Error"><Setter Property="Background" Value="{DynamicResource DxSevCritBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevCritFg}"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowWarnAll" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxSevWarnBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevWarnFg}"/>
      <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger></Style.Triggers>
    </Style>
    <Style x:Key="RowErrAll" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxSevErrBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevErrFg}"/>
      <Style.Triggers><Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger></Style.Triggers>
    </Style>
    <Style x:Key="RowCse" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxSevErrBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevErrFg}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding Status}" Value="Success"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
    <Style x:Key="RowApp" TargetType="DataGridRow">
      <Setter Property="Background" Value="{DynamicResource DxCardBg}"/><Setter Property="Foreground" Value="{DynamicResource DxInk}"/>
      <Style.Triggers>
        <DataTrigger Binding="{Binding ErrorCode}" Value="0"><Setter Property="Background" Value="{DynamicResource DxSevOkBg}"/><Setter Property="Foreground" Value="{DynamicResource DxSevOkFg}"/></DataTrigger>
        <Trigger Property="IsMouseOver" Value="True"><Setter Property="Background" Value="{DynamicResource DxRowHover}"/></Trigger>
        <Trigger Property="IsSelected" Value="True"><Setter Property="Background" Value="{DynamicResource DxAccent}"/><Setter Property="Foreground" Value="{DynamicResource DxOnAccent}"/></Trigger>
      </Style.Triggers>
    </Style>
  </Window.Resources>

  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- HEADER -->
    <!-- Background is repainted by Set-DxTheme (see Set-DxHeaderBrush).
         GradientStop.Color takes a Color, not a Brush, so the theme brushes
         cannot be referenced here - the stops below are the Light defaults
         and exist only so the header is painted before the theme loads. -->
    <Border x:Name="brdHeader" Grid.Row="0" Padding="20,13">
      <Border.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
          <GradientStop Color="#FF111A2C" Offset="0"/><GradientStop Color="#FF1C2740" Offset="0.55"/><GradientStop Color="#FF2E2C86" Offset="1"/>
        </LinearGradientBrush>
      </Border.Background>
      <Grid>
        <StackPanel Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Width="42" Height="42" CornerRadius="11" Background="{DynamicResource DxHeadChipBg}" Margin="0,0,12,0">
          <Grid>
          <Image x:Name="imgLogo" Width="34" Height="34" Stretch="Uniform"
          RenderOptions.BitmapScalingMode="HighQuality"/>
          <TextBlock x:Name="lblLogoFallback" Text="@" Foreground="White" FontSize="24"
          FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Center"
          Visibility="Collapsed"/>
          </Grid>
          </Border>
<StackPanel VerticalAlignment="Center">
            <TextBlock Text="Sys@dmin" Foreground="White" FontSize="20" FontWeight="SemiBold"/>
            <TextBlock x:Name="lblSubtitle" Text="Windows Endpoint Diagnostics Console" Foreground="{DynamicResource DxHeadFgSoft}" FontSize="11.5"/>
          </StackPanel>
        </StackPanel>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" VerticalAlignment="Center">
          <Border x:Name="badgeElev" Background="{DynamicResource DxBadgeOk}" CornerRadius="13" Padding="12,5" Margin="0,0,9,0">
            <TextBlock x:Name="lblElev" Text="Elevated" Foreground="White" FontSize="11" FontWeight="SemiBold"/>
          </Border>
          <Border Background="{DynamicResource DxHeadChipBg}" CornerRadius="13" Padding="12,5" Margin="0,0,9,0">
            <TextBlock x:Name="lblHost" Text="HOST" Foreground="White" FontSize="11"/>
          </Border>
          <Border Background="{DynamicResource DxHeadChipBg}" CornerRadius="13" Padding="12,5">
            <TextBlock x:Name="lblSerial" Text="S/N ..." Foreground="White" FontSize="11"/>
          </Border>
        </StackPanel>
      </Grid>
    </Border>

    <!-- TOOLBAR -->
    <Border Grid.Row="1" Background="{DynamicResource DxCardBg}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="0,0,0,1" Padding="16,9">
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="Time window" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
        <ComboBox x:Name="cboHours" Width="130" Height="28" VerticalContentAlignment="Center" Margin="0,0,16,0">
          <ComboBoxItem Content="Last 1 hour" Tag="1"/><ComboBoxItem Content="Last 8 hours" Tag="8"/>
          <ComboBoxItem Content="Last 24 hours" Tag="24" IsSelected="True"/><ComboBoxItem Content="Last 3 days" Tag="72"/>
          <ComboBoxItem Content="Last 7 days" Tag="168"/><ComboBoxItem Content="Last 30 days" Tag="720"/>
        </ComboBox>
        <CheckBox x:Name="chkCritical" Content="Critical" IsChecked="True" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="{DynamicResource DxSevCritFg}" FontWeight="SemiBold"/>
        <CheckBox x:Name="chkError" Content="Error" IsChecked="True" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="{DynamicResource DxSevErrFg}"/>
        <CheckBox x:Name="chkWarning" Content="Warning" IsChecked="True" VerticalAlignment="Center" Margin="0,0,10,0" Foreground="{DynamicResource DxSevWarnFg}"/>
        <CheckBox x:Name="chkInfo" Content="Information" VerticalAlignment="Center" Margin="0,0,16,0" Foreground="{DynamicResource DxSevInfoFg}"/>
        <Button x:Name="btnScan" Content="Run full scan"/>
        <Button x:Name="btnEvents" Content="Refresh events" Style="{StaticResource BtnGhost}"/>
        <Button x:Name="btnExport" Content="Export HTML report" Style="{StaticResource BtnOk}"/>
        <Button x:Name="btnDiag" Content="Collector diagnostic" Style="{StaticResource BtnWarn}"/>
        <Button x:Name="btnTheme" Content="Dark mode" Style="{StaticResource BtnGhost}"/>
        <Button x:Name="btnNavToggle" Content="Collapse menu" Style="{StaticResource BtnGhost}"/>
      </StackPanel>
    </Border>

    <TabControl Grid.Row="2" x:Name="tabs" Style="{StaticResource SideNav}" Margin="0,0,0,2">

      <!-- DASHBOARD -->
      <TabItem x:Name="tabDash" Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M3,13h8V3H3V13z M3,21h8v-6H3V21z M13,21h8V11h-8V21z M13,3v6h8V3H13z"/>
            <TextBlock Text="Dashboard" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>

        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="3*" MinHeight="150"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="4*" MinHeight="150"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="3*" MinHeight="120"/>
          </Grid.RowDefinitions>

          <!-- Six DISTINCT dimensions. The severity counts live in the donut
               legend below rather than being restated here. -->
          <UniformGrid Grid.Row="0" Rows="1" Columns="6">
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSpotBg}" BorderBrush="{DynamicResource DxSpotEdge}">
              <StackPanel><TextBlock Text="HEALTH SCORE" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSpotMuted}"/>
              <TextBlock x:Name="kpiScore" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSpotFg}"/>
              <TextBlock x:Name="kpiGrade" Text="not scanned" FontSize="11" Foreground="{DynamicResource DxSpotMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevCritBg}" BorderBrush="{DynamicResource DxSevCritEdge}">
              <StackPanel><TextBlock Text="EVENTS IN WINDOW" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="kpiEvents" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="lblEventMix" Text="no scan yet" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOkBg2}" BorderBrush="{DynamicResource DxSevOkEdge}">
              <StackPanel><TextBlock Text="SECURITY POSTURE" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="kpiPosture" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="lblPostureNote" Text="not checked" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevInfoBg2}" BorderBrush="{DynamicResource DxSevInfoEdge}">
              <StackPanel><TextBlock Text="TIGHTEST VOLUME" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="kpiStorage" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="lblStorageNote" Text="free space" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxAccentSoftBg}" BorderBrush="{DynamicResource DxAccentSoftEdge}">
              <StackPanel><TextBlock Text="MEMORY IN USE" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="kpiMemory" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="lblMemoryNote" Text="physical RAM" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevWarnBg2}" BorderBrush="{DynamicResource DxSevWarnEdge}">
              <StackPanel><TextBlock Text="UPTIME" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevWarnFg}"/>
              <TextBlock x:Name="kpiUptime" Text="--" FontSize="18" FontWeight="SemiBold" Foreground="{DynamicResource DxSevWarnFg}" Margin="0,6,0,0"/>
              <TextBlock x:Name="kpiReboot" Text="" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
          </UniformGrid>

          <!-- Boolean state belongs in chips, not in a number and not buried
               in a key/value grid. Built at runtime by Update-DxPostureStrip. -->
          <Border Grid.Row="1" Style="{StaticResource Card}">
            <DockPanel>
              <TextBlock DockPanel.Dock="Top" Text="SYSTEM AT A GLANCE" Style="{StaticResource CardTitle}"/>
              <WrapPanel x:Name="spPosture" Orientation="Horizontal" Margin="0,2,0,0"/>
            </DockPanel>
          </Border>

          <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto" MinWidth="230"/>
              <ColumnDefinition Width="*" MinWidth="180"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="180"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="EVENT SEVERITY MIX" Style="{StaticResource CardTitle}"/>
              <StackPanel Orientation="Horizontal" HorizontalAlignment="Center" VerticalAlignment="Center">
                <Canvas x:Name="cvSeverity" Width="160" Height="160"/>
                <StackPanel x:Name="spSeverityLegend" VerticalAlignment="Center" Margin="12,0,0,0"/>
              </StackPanel></DockPanel>
            </Border>
            <Border Grid.Column="1" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="TOP EVENT SOURCES" Style="{StaticResource CardTitle}"/>
              <Canvas x:Name="cvProviders"/></DockPanel>
            </Border>
            <GridSplitter Grid.Column="2" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="3" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="EVENTS OVER TIME" Style="{StaticResource CardTitle}"/>
              <Canvas x:Name="cvTimeline"/></DockPanel>
            </Border>
          </Grid>

          <GridSplitter Grid.Row="3" Style="{StaticResource HSplit}"/>

          <Grid Grid.Row="4">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" MinWidth="200"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="190"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="200"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="DEVICE" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridSystem">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Property" Binding="{Binding Property}" Width="150"/>
                  <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
            <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
            <!-- Free space is a percentage against a ceiling, so it is bars,
                 not another table of numbers. -->
            <Border Grid.Column="2" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="VOLUME HEADROOM  (% used)" Style="{StaticResource CardTitle}"/>
              <Canvas x:Name="cvDashDisks"/></DockPanel>
            </Border>
            <GridSplitter Grid.Column="3" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="4" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="WHY THE SCORE WAS REDUCED" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridDeduct">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Points" Binding="{Binding Points}" Width="60"/>
                  <DataGridTextColumn Header="Area" Binding="{Binding Area}" Width="130"/>
                  <DataGridTextColumn Header="Reason" Binding="{Binding Reason}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
          </Grid>

          <GridSplitter Grid.Row="5" Style="{StaticResource HSplit}"/>

          <Border Grid.Row="6" Style="{StaticResource Card}">
            <DockPanel><TextBlock DockPanel.Dock="Top" Text="TOP RECURRING ISSUES  (double-click to open the resolution)" Style="{StaticResource CardTitle}"/>
            <DataGrid x:Name="gridTop" RowStyle="{StaticResource RowLevel}">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="76"/>
                <DataGridTextColumn Header="Count" Binding="{Binding Count}" Width="60"/>
                <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="56"/>
                <DataGridTextColumn Header="Provider" Binding="{Binding Provider}" Width="220"/>
                <DataGridTextColumn Header="Issue" Binding="{Binding Title}" Width="*"/>
              </DataGrid.Columns>
            </DataGrid></DockPanel>
          </Border>
        </Grid>
      
      </TabItem>

      <!-- EVENT ANALYSIS -->
      <!-- EVENTS  (Event Analysis + Resolutions merged) -->
      <TabItem x:Name="tabEvents" Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M4,3h16v2H4V3z M4,7h16v2H4V7z M4,11h10v2H4V11z M4,15h10v2H4V15z M16.5,12l4.5,8h-9L16.5,12z"/>
            <TextBlock Text="Events" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <TabControl x:Name="eventSubTabs" Margin="4" Background="{DynamicResource DxTabStripBg}" BorderBrush="{DynamicResource DxCardBorder}">
          <TabItem Header="Event analysis" x:Name="tabEventList">
          <Grid Margin="8">
            <Grid.RowDefinitions>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="3*" MinHeight="150"/>
              <RowDefinition Height="Auto"/>
              <RowDefinition Height="*" MinHeight="90"/>
            </Grid.RowDefinitions>
            <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
              <TextBlock Text="Log" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
              <ComboBox x:Name="cboLog" Width="300" Height="27" IsEditable="True" Margin="0,0,10,0"/>
              <TextBlock Text="Contains" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
              <TextBox x:Name="txtFilter" Width="220" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,0"/>
              <Button x:Name="btnFilter" Content="Apply filter"/>
              <Button x:Name="btnEventDetail" Content="View full detail" Style="{StaticResource BtnOk}"/>
              <Button x:Name="btnAddLog" Content="Add channel" Style="{StaticResource BtnGhost}"/>
              <TextBlock x:Name="lblEventCount" Text="" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{DynamicResource DxMuted}"/>
            </StackPanel>
            <DataGrid Grid.Row="1" x:Name="gridEvents" RowStyle="{StaticResource RowLevel}">
              <DataGrid.Columns>
                <DataGridTextColumn Header="Time" Binding="{Binding TimeCreated}" Width="140"/>
                <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="76"/>
                <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="56"/>
                <DataGridTextColumn Header="Provider" Binding="{Binding Provider}" Width="230"/>
                <DataGridTextColumn Header="Log" Binding="{Binding LogName}" Width="170"/>
                <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
              </DataGrid.Columns>
            </DataGrid>
            <GridSplitter Grid.Row="2" Style="{StaticResource HSplit}"/>
            <Border Grid.Row="3" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="1" Background="{DynamicResource DxSubtle}" CornerRadius="8">
              <ScrollViewer VerticalScrollBarVisibility="Auto">
                <TextBox x:Name="txtEventDetail" IsReadOnly="True" TextWrapping="Wrap" BorderThickness="0" Background="Transparent" Padding="10" FontFamily="Consolas" FontSize="11.5"/>
              </ScrollViewer>
            </Border>
          </Grid>
          </TabItem>
          <TabItem Header="Resolutions" x:Name="tabResolutions">
          <Grid Margin="8">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="2*" MinWidth="240"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="3*" MinWidth="300"/>
            </Grid.ColumnDefinitions>
            <DockPanel Grid.Column="0">
              <TextBlock DockPanel.Dock="Top" Text="DETECTED ISSUE SIGNATURES" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridIssues" RowStyle="{StaticResource RowLevel}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="70"/>
                  <DataGridTextColumn Header="No." Binding="{Binding Count}" Width="45"/>
                  <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="55"/>
                  <DataGridTextColumn Header="Issue" Binding="{Binding Title}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </DockPanel>
            <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="2" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="1" Background="{DynamicResource DxCardBg}" CornerRadius="12">
              <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="16">
                <StackPanel>
                  <TextBlock x:Name="resTitle" Text="Select an issue on the left" FontSize="16" FontWeight="SemiBold" TextWrapping="Wrap" Foreground="{DynamicResource DxInk}"/>
                  <TextBlock x:Name="resMeta" Text="" Foreground="{DynamicResource DxMuted}" Margin="0,5,0,12" TextWrapping="Wrap" FontSize="11.5"/>
                  <TextBlock Text="LIKELY CAUSE" Style="{StaticResource CardTitle}" Margin="0,0,0,4"/>
                  <TextBlock x:Name="resCause" Text="" TextWrapping="Wrap" Margin="0,0,0,12"/>
                  <TextBlock Text="IMPACT" Style="{StaticResource CardTitle}" Margin="0,0,0,4"/>
                  <TextBlock x:Name="resImpact" Text="" TextWrapping="Wrap" Margin="0,0,0,12"/>
                  <TextBlock Text="RESOLUTION STEPS" Style="{StaticResource CardTitle}" Margin="0,0,0,4"/>
                  <ItemsControl x:Name="resSteps" Margin="0,4,0,12">
                    <ItemsControl.ItemTemplate><DataTemplate>
                      <Border Background="{DynamicResource DxSubtle}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="1" CornerRadius="7" Padding="10,7" Margin="0,0,0,5">
                        <TextBlock Text="{Binding}" TextWrapping="Wrap"/>
                      </Border>
                    </DataTemplate></ItemsControl.ItemTemplate>
                  </ItemsControl>
                  <TextBlock Text="COMMANDS  (double-click to copy)" Style="{StaticResource CardTitle}" Margin="0,0,0,4"/>
                  <ListBox x:Name="lstCommands" Margin="0,4,0,12" MaxHeight="180" Background="{DynamicResource DxConsoleBg}" Foreground="{DynamicResource DxSpotFg}" BorderThickness="0" FontFamily="Consolas" FontSize="11.5"/>
                  <TextBlock Text="SAMPLE EVENT TEXT" Style="{StaticResource CardTitle}" Margin="0,0,0,4"/>
                  <TextBox x:Name="resSample" IsReadOnly="True" TextWrapping="Wrap" Margin="0,4,0,12" Background="{DynamicResource DxSubtle}" BorderBrush="{DynamicResource DxCardBorder}" Padding="8" MaxHeight="120" VerticalScrollBarVisibility="Auto" FontFamily="Consolas" FontSize="11"/>
                  <StackPanel Orientation="Horizontal">
                    <Button x:Name="btnDocs" Content="Open Microsoft docs"/>
                    <Button x:Name="btnCopyAll" Content="Copy full resolution" Style="{StaticResource BtnGhost}"/>
                  </StackPanel>
                </StackPanel>
              </ScrollViewer>
            </Border>
          </Grid>
          </TabItem>
        </TabControl>
      </TabItem>
'@

$xamlText += @'

      <!-- NETWORK -->
      <TabItem x:Name="tabNet" Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M12,2C8.1,2,5,5.1,5,9c0,1.9,0.8,3.6,2,4.9V22h10v-8.1c1.2-1.3,2-3,2-4.9C19,5.1,15.9,2,12,2z M12,4c2.8,0,5,2.2,5,5s-2.2,5-5,5s-5-2.2-5-5S9.2,4,12,4z M11,16h2v4h-2V16z"/>
            <TextBlock Text="Network" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <Grid Margin="8">
          <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,8">
            <Button x:Name="btnNetScan" Content="Analyse firewall and DNS"/>
            <Button x:Name="btnNetAdapters" Content="Refresh adapters" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnFlushDns" Content="Flush DNS cache" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnWf" Content="Firewall console" Style="{StaticResource BtnGhost}"/>
            <TextBlock x:Name="lblNetSummary" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/>
          </StackPanel>

          <TabControl Grid.Row="1" x:Name="netSubTabs" Background="{DynamicResource DxTabStripBg}" BorderBrush="{DynamicResource DxCardBorder}">

            <!-- FIREWALL -->
            <TabItem Header="Firewall" x:Name="tabFw">
              <Grid Margin="4">
                <Grid.RowDefinitions>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="2*" MinHeight="110"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="3*" MinHeight="130"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="2*" MinHeight="110"/>
                </Grid.RowDefinitions>

                <UniformGrid Grid.Row="0" Rows="1" Columns="5">
                  <Border Style="{StaticResource Card}" Background="{DynamicResource DxSpotBg}" BorderBrush="{DynamicResource DxSpotEdge}">
                    <StackPanel><TextBlock Text="FIREWALL SERVICE" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSpotMuted}"/>
                    <TextBlock x:Name="kpiFwSvc" Text="--" FontSize="17" FontWeight="Bold" Foreground="White" Margin="0,6,0,0"/></StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOkBg2}" BorderBrush="{DynamicResource DxSevOkEdge}">
                    <StackPanel><TextBlock Text="PROFILES ON" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOkFg}"/>
                    <TextBlock x:Name="kpiFwOn" Text="0/3" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevOkFg}"/></StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Background="{DynamicResource DxAccentSoftBg}" BorderBrush="{DynamicResource DxAccentSoftEdge}">
                    <StackPanel><TextBlock Text="ENABLED RULES" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxAccent}"/>
                    <TextBlock x:Name="kpiFwRules" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxAccent}"/></StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevInfoBg}" BorderBrush="{DynamicResource DxSevInfoEdge2}">
                    <StackPanel><TextBlock Text="INBOUND ALLOW" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevInfoFg}"/>
                    <TextBlock x:Name="kpiFwInAllow" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevInfoFg}"/></StackPanel>
                  </Border>
                  <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevCritBg}" BorderBrush="{DynamicResource DxSevCritEdge}">
                    <StackPanel><TextBlock Text="BLOCKED EVENTS" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevCritFg}"/>
                    <TextBlock x:Name="kpiFwBlocked" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevCritFg}"/></StackPanel>
                  </Border>
                </UniformGrid>

                <Grid Grid.Row="1">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" MinWidth="200"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="180"/>
                  </Grid.ColumnDefinitions>
                  <Border Grid.Column="0" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="PROFILES" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridFwProfiles" RowStyle="{StaticResource RowFwProfile}">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Profile" Binding="{Binding Profile}" Width="75"/>
                        <DataGridTextColumn Header="State" Binding="{Binding Status}" Width="75"/>
                        <DataGridTextColumn Header="Inbound" Binding="{Binding DefaultInboundAction}" Width="75"/>
                        <DataGridTextColumn Header="Outbound" Binding="{Binding DefaultOutboundAction}" Width="75"/>
                        <DataGridTextColumn Header="Log" Binding="{Binding LogBlocked}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="2" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="ACTIVE NETWORK PROFILES" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridFwConn">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Interface" Binding="{Binding Interface}" Width="130"/>
                        <DataGridTextColumn Header="Network" Binding="{Binding NetworkName}" Width="140"/>
                        <DataGridTextColumn Header="Category" Binding="{Binding Category}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="3" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="4" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="RULE MIX" Style="{StaticResource CardTitle}"/>
                    <Canvas x:Name="cvFwRules"/></DockPanel>
                  </Border>
                </Grid>

                <GridSplitter Grid.Row="2" Style="{StaticResource HSplit}"/>

                <Border Grid.Row="3" Style="{StaticResource Card}">
                  <DockPanel>
                    <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,6">
                      <TextBlock x:Name="lblFwRulesTitle" Text="ENABLED RULES" Style="{StaticResource CardTitle}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                      <ComboBox x:Name="cboFwDir" Width="100" Height="25" VerticalContentAlignment="Center" Margin="0,0,6,0">
                        <ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="Inbound"/><ComboBoxItem Content="Outbound"/>
                      </ComboBox>
                      <ComboBox x:Name="cboFwAction" Width="90" Height="25" VerticalContentAlignment="Center" Margin="0,0,6,0">
                        <ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="Allow"/><ComboBoxItem Content="Block"/>
                      </ComboBox>
                      <TextBox x:Name="txtFwFind" Width="200" Height="25" VerticalContentAlignment="Center" Margin="0,0,6,0"/>
                      <Button x:Name="btnFwFind" Content="Search" Style="{StaticResource BtnMini}"/>
                      <TextBlock x:Name="lblFwRows" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{DynamicResource DxMuted}"/>
                    </StackPanel>
                    <DataGrid x:Name="gridFwRules" RowStyle="{StaticResource RowFwRule}">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Rule" Binding="{Binding DisplayName}" Width="280"/>
                        <DataGridTextColumn Header="Dir" Binding="{Binding Direction}" Width="70"/>
                        <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="65"/>
                        <DataGridTextColumn Header="Profile" Binding="{Binding Profile}" Width="105"/>
                        <DataGridTextColumn Header="Proto" Binding="{Binding Protocol}" Width="60"/>
                        <DataGridTextColumn Header="Local port" Binding="{Binding LocalPort}" Width="95"/>
                        <DataGridTextColumn Header="Group" Binding="{Binding Group}" Width="170"/>
                        <DataGridTextColumn Header="Program" Binding="{Binding Program}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid>
                  </DockPanel>
                </Border>

                <GridSplitter Grid.Row="4" Style="{StaticResource HSplit}"/>

                <Grid Grid.Row="5">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="160"/>
                  </Grid.ColumnDefinitions>
                  <Border Grid.Column="0" Style="{StaticResource Card}">
                    <DockPanel><TextBlock x:Name="lblFwLog" DockPanel.Dock="Top" Text="FIREWALL LOG" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridFwLog" RowStyle="{StaticResource RowFwLog}">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="125"/>
                        <DataGridTextColumn Header="Action" Binding="{Binding Action}" Width="60"/>
                        <DataGridTextColumn Header="Proto" Binding="{Binding Protocol}" Width="52"/>
                        <DataGridTextColumn Header="Source" Binding="{Binding SrcIp}" Width="110"/>
                        <DataGridTextColumn Header="Destination" Binding="{Binding DstIp}" Width="110"/>
                        <DataGridTextColumn Header="Port" Binding="{Binding DstPort}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="2" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="BLOCKED CONNECTIONS  (audit 5152 / 5157)" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridFwBlocked" RowStyle="{StaticResource RowErrAll}">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="125"/>
                        <DataGridTextColumn Header="Kind" Binding="{Binding Kind}" Width="120"/>
                        <DataGridTextColumn Header="Application" Binding="{Binding Application}" Width="200"/>
                        <DataGridTextColumn Header="Destination" Binding="{Binding Destination}" Width="110"/>
                        <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="3" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="4" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="FINDINGS" Style="{StaticResource CardTitle}"/>
                    <ListBox x:Name="lstFwFindings" FontSize="11.5" BorderThickness="0" HorizontalContentAlignment="Stretch">
                      <ListBox.ItemTemplate><DataTemplate>
                        <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,2"/>
                      </DataTemplate></ListBox.ItemTemplate>
                    </ListBox></DockPanel>
                  </Border>
                </Grid>
              </Grid>
            </TabItem>

            <!-- DNS -->
            <TabItem Header="DNS" x:Name="tabDns">
              <Grid Margin="4">
                <Grid.RowDefinitions>
                  <RowDefinition Height="2*" MinHeight="110"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="2*" MinHeight="110"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="3*" MinHeight="120"/>
                </Grid.RowDefinitions>

                <Grid Grid.Row="0">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" MinWidth="200"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="200"/>
                  </Grid.ColumnDefinitions>
                  <Border Grid.Column="0" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="CONFIGURED DNS SERVERS" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridDnsServers">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Interface" Binding="{Binding Interface}" Width="170"/>
                        <DataGridTextColumn Header="Servers" Binding="{Binding Servers}" Width="*"/>
                        <DataGridTextColumn Header="No." Binding="{Binding Count}" Width="45"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="2" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="SERVER REACHABILITY" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridDnsReach" RowStyle="{StaticResource RowBool}">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Server" Binding="{Binding Server}" Width="125"/>
                        <DataGridTextColumn Header="Interface" Binding="{Binding Interface}" Width="150"/>
                        <DataGridTextColumn Header="TCP 53" Binding="{Binding TcpPort53}" Width="65"/>
                        <DataGridTextColumn Header="ICMP" Binding="{Binding IcmpReply}" Width="60"/>
                        <DataGridTextColumn Header="Reachable" Binding="{Binding Reachable}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                </Grid>

                <GridSplitter Grid.Row="1" Style="{StaticResource HSplit}"/>

                <Grid Grid.Row="2">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="180"/>
                  </Grid.ColumnDefinitions>
                  <Border Grid.Column="0" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="RESOLUTION TIME  (ms)" Style="{StaticResource CardTitle}"/>
                    <Canvas x:Name="cvDnsProbe"/></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="2" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="RESOLUTION PROBES" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridDnsProbes" RowStyle="{StaticResource RowResolved}">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="180"/>
                        <DataGridTextColumn Header="OK" Binding="{Binding Resolved}" Width="55"/>
                        <DataGridTextColumn Header="ms" Binding="{Binding Ms}" Width="50"/>
                        <DataGridTextColumn Header="Addresses" Binding="{Binding Addresses}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="3" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="4" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="FINDINGS" Style="{StaticResource CardTitle}"/>
                    <ListBox x:Name="lstDnsFindings" FontSize="11.5" BorderThickness="0" HorizontalContentAlignment="Stretch">
                      <ListBox.ItemTemplate><DataTemplate>
                        <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,2"/>
                      </DataTemplate></ListBox.ItemTemplate>
                    </ListBox></DockPanel>
                  </Border>
                </Grid>

                <GridSplitter Grid.Row="3" Style="{StaticResource HSplit}"/>

                <Grid Grid.Row="4">
                  <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="2*" MinWidth="250"/><ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*" MinWidth="180"/>
                  </Grid.ColumnDefinitions>
                  <Border Grid.Column="0" Style="{StaticResource Card}">
                    <DockPanel>
                      <StackPanel DockPanel.Dock="Top" Orientation="Horizontal" Margin="0,0,0,6">
                        <TextBlock Text="RESOLVER CACHE" Style="{StaticResource CardTitle}" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBox x:Name="txtDnsCacheFind" Width="180" Height="25" VerticalContentAlignment="Center" Margin="0,0,6,0"/>
                        <Button x:Name="btnDnsCacheFind" Content="Search" Style="{StaticResource BtnMini}"/>
                        <Button x:Name="btnDnsCacheRefresh" Content="Refresh" Style="{StaticResource BtnMini}" Background="{DynamicResource DxGhost}"/>
                        <TextBlock x:Name="lblDnsCacheRows" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{DynamicResource DxMuted}"/>
                      </StackPanel>
                      <DataGrid x:Name="gridDnsCache">
                        <DataGrid.Columns>
                          <DataGridTextColumn Header="Entry" Binding="{Binding Entry}" Width="230"/>
                          <DataGridTextColumn Header="Record" Binding="{Binding Name}" Width="210"/>
                          <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="70"/>
                          <DataGridTextColumn Header="TTL" Binding="{Binding TTL}" Width="65"/>
                          <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="105"/>
                          <DataGridTextColumn Header="Data" Binding="{Binding Data}" Width="*"/>
                        </DataGrid.Columns>
                      </DataGrid>
                    </DockPanel>
                  </Border>
                  <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                  <Border Grid.Column="2" Style="{StaticResource Card}">
                    <DockPanel><TextBlock DockPanel.Dock="Top" Text="SUFFIXES AND NRPT" Style="{StaticResource CardTitle}"/>
                    <DataGrid x:Name="gridDnsSuffix">
                      <DataGrid.Columns>
                        <DataGridTextColumn Header="Interface" Binding="{Binding Interface}" Width="145"/>
                        <DataGridTextColumn Header="Suffix" Binding="{Binding Suffix}" Width="160"/>
                        <DataGridTextColumn Header="Register" Binding="{Binding RegisterAddress}" Width="*"/>
                      </DataGrid.Columns>
                    </DataGrid></DockPanel>
                  </Border>
                </Grid>
              </Grid>
            </TabItem>

            <!-- PING -->
            <TabItem Header="Ping" x:Name="tabPing">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Grid.Row="0" Style="{StaticResource Card}">
                  <StackPanel>
                    <WrapPanel Orientation="Horizontal">
                      <TextBlock Text="Target" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <TextBox x:Name="txtPingTarget" Width="210" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,4"/>
                      <TextBlock Text="Interval" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <ComboBox x:Name="cboPingInterval" Width="90" Height="27" VerticalContentAlignment="Center" Margin="0,0,10,4">
                        <ComboBoxItem Content="0.5 s" Tag="500"/><ComboBoxItem Content="1 s" Tag="1000" IsSelected="True"/>
                        <ComboBoxItem Content="2 s" Tag="2000"/><ComboBoxItem Content="5 s" Tag="5000"/>
                      </ComboBox>
                      <Button x:Name="btnPingAdd" Content="Add ping card"/>
                      <Button x:Name="btnPingStartAll" Content="Start all" Style="{StaticResource BtnOk}"/>
                      <Button x:Name="btnPingStopAll" Content="Stop all" Style="{StaticResource BtnWarn}"/>
                      <Button x:Name="btnPingClearAll" Content="Remove all" Style="{StaticResource BtnDanger}"/>
                      <Button x:Name="btnPingPreset" Content="Add standard set" Style="{StaticResource BtnGhost}"/>
                    </WrapPanel>
                    <TextBlock Margin="0,4,0,0" Foreground="{DynamicResource DxMuted}" FontSize="11.5" TextWrapping="Wrap"
                               Text="Each card pings independently on its own timer. Add the gateway, your DNS servers and an internet host, then leave them running while you reproduce the fault - the sparkline makes packet loss and latency spikes obvious."/>
                  </StackPanel>
                </Border>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="2">
                  <WrapPanel x:Name="pingPanel" Orientation="Horizontal"/>
                </ScrollViewer>
              </Grid>
            </TabItem>

            <!-- LOOKUP -->
            <TabItem Header="Lookup" x:Name="tabLookup">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Grid.Row="0" Style="{StaticResource Card}">
                  <StackPanel>
                    <WrapPanel Orientation="Horizontal">
                      <TextBlock Text="Name" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <TextBox x:Name="txtLookupName" Width="210" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,4"/>
                      <TextBlock Text="Type" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <ComboBox x:Name="cboLookupType" Width="88" Height="27" VerticalContentAlignment="Center" Margin="0,0,10,4">
                        <ComboBoxItem Content="A" IsSelected="True"/><ComboBoxItem Content="AAAA"/><ComboBoxItem Content="CNAME"/>
                        <ComboBoxItem Content="MX"/><ComboBoxItem Content="NS"/><ComboBoxItem Content="TXT"/>
                        <ComboBoxItem Content="SRV"/><ComboBoxItem Content="PTR"/><ComboBoxItem Content="SOA"/><ComboBoxItem Content="ALL"/>
                      </ComboBox>
                      <TextBlock Text="Server" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <TextBox x:Name="txtLookupServer" Width="140" Height="27" VerticalContentAlignment="Center" Margin="0,0,10,4" ToolTip="Optional - blank uses the adapter DNS servers"/>
                      <Button x:Name="btnLookupAdd" Content="Add lookup card"/>
                      <Button x:Name="btnLookupRunAll" Content="Run all" Style="{StaticResource BtnOk}"/>
                      <Button x:Name="btnLookupClearAll" Content="Remove all" Style="{StaticResource BtnDanger}"/>
                      <Button x:Name="btnLookupPreset" Content="Add standard set" Style="{StaticResource BtnGhost}"/>
                    </WrapPanel>
                    <TextBlock Margin="0,4,0,0" Foreground="{DynamicResource DxMuted}" FontSize="11.5" TextWrapping="Wrap"
                               Text="Each card is an independent nslookup. Point one card at internal DNS and another at a public resolver with the same name to prove split-brain DNS or an NRPT rule in seconds."/>
                  </StackPanel>
                </Border>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="2">
                  <WrapPanel x:Name="lookupPanel" Orientation="Horizontal"/>
                </ScrollViewer>
              </Grid>
            </TabItem>

            <!-- TRACE ROUTE -->
            <TabItem Header="Trace Route" x:Name="tabTrace">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Grid.Row="0" Style="{StaticResource Card}">
                  <StackPanel>
                    <WrapPanel Orientation="Horizontal">
                      <TextBlock Text="Target" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <TextBox x:Name="txtTraceTarget" Width="200" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,4"/>
                      <TextBlock Text="Max hops" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <ComboBox x:Name="cboTraceHops" Width="70" Height="27" VerticalContentAlignment="Center" Margin="0,0,10,4">
                        <ComboBoxItem Content="15" Tag="15"/><ComboBoxItem Content="30" Tag="30" IsSelected="True"/><ComboBoxItem Content="45" Tag="45"/>
                      </ComboBox>
                      <CheckBox x:Name="chkTraceNames" Content="Resolve names" IsChecked="True" VerticalAlignment="Center" Margin="0,0,10,4" Foreground="{DynamicResource DxHeaderFg}"/>
                      <Button x:Name="btnTraceAdd" Content="Add trace card"/>
                      <Button x:Name="btnTraceRunAll" Content="Run all" Style="{StaticResource BtnOk}"/>
                      <Button x:Name="btnTraceStopAll" Content="Stop all" Style="{StaticResource BtnWarn}"/>
                      <Button x:Name="btnTraceClearAll" Content="Remove all" Style="{StaticResource BtnDanger}"/>
                      <Button x:Name="btnTracePreset" Content="Add standard set" Style="{StaticResource BtnGhost}"/>
                    </WrapPanel>
                    <TextBlock Margin="0,4,0,0" Foreground="{DynamicResource DxMuted}" FontSize="11.5" TextWrapping="Wrap"
                               Text="Each card traces independently, one hop at a time, so the route builds up live. Routers commonly suppress ICMP, so isolated gaps are normal - only a gap that never recovers indicates a real break."/>
                  </StackPanel>
                </Border>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="2">
                  <WrapPanel x:Name="tracePanel" Orientation="Horizontal"/>
                </ScrollViewer>
              </Grid>
            </TabItem>

            <!-- PORT CHECK -->
            <TabItem Header="Port Check" x:Name="tabPort">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <Border Grid.Row="0" Style="{StaticResource Card}">
                  <StackPanel>
                    <WrapPanel Orientation="Horizontal">
                      <TextBlock Text="Target" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <TextBox x:Name="txtPortTarget" Width="190" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,4"/>
                      <TextBlock Text="Ports" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                      <TextBox x:Name="txtPortList" Width="210" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,4"
                               Text="443,80" ToolTip="Comma separated. Ranges allowed, for example 443,80,3389,5985-5986"/>
                      <ComboBox x:Name="cboPortPreset" Width="145" Height="27" VerticalContentAlignment="Center" Margin="0,0,10,4">
                        <ComboBoxItem Content="Preset..." IsSelected="True" Tag=""/>
                        <ComboBoxItem Content="Web" Tag="80,443,8080,8443"/>
                        <ComboBoxItem Content="Domain controller" Tag="53,88,135,389,445,464,636,3268,3269,9389"/>
                        <ComboBoxItem Content="Remote management" Tag="135,445,3389,5985,5986,47001"/>
                        <ComboBoxItem Content="Mail" Tag="25,110,143,465,587,993,995"/>
                        <ComboBoxItem Content="Database" Tag="1433,1434,1521,3306,5432,6379,27017"/>
                        <ComboBoxItem Content="WSUS / SCCM" Tag="80,443,8530,8531,10123"/>
                        <ComboBoxItem Content="File and print" Tag="139,445,515,631,9100"/>
                      </ComboBox>
                      <Button x:Name="btnPortAdd" Content="Add port card"/>
                      <Button x:Name="btnPortRunAll" Content="Run all" Style="{StaticResource BtnOk}"/>
                      <Button x:Name="btnPortStopAll" Content="Stop all" Style="{StaticResource BtnWarn}"/>
                      <Button x:Name="btnPortClearAll" Content="Remove all" Style="{StaticResource BtnDanger}"/>
                      <Button x:Name="btnPortPreset" Content="Add cloud set" Style="{StaticResource BtnGhost}"/>
                    </WrapPanel>
                    <TextBlock Margin="0,4,0,0" Foreground="{DynamicResource DxMuted}" FontSize="11.5" TextWrapping="Wrap"
                               Text="Use this rather than ping for cloud endpoints - most of them drop ICMP but answer on 443, so a failed ping proves nothing while a failed port check is real evidence."/>
                  </StackPanel>
                </Border>
                <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto" Padding="2">
                  <WrapPanel x:Name="portPanel" Orientation="Horizontal"/>
                </ScrollViewer>
              </Grid>
            </TabItem>

            <!-- ADAPTERS -->
            <TabItem Header="Adapters">
              <Grid Margin="4">
                <Grid.RowDefinitions>
                  <RowDefinition Height="*" MinHeight="110"/>
                  <RowDefinition Height="Auto"/>
                  <RowDefinition Height="*" MinHeight="110"/>
                </Grid.RowDefinitions>
                <Border Grid.Row="0" Style="{StaticResource Card}">
                  <DockPanel><TextBlock DockPanel.Dock="Top" Text="NETWORK ADAPTERS" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridAdapters">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="140"/>
                      <DataGridTextColumn Header="Description" Binding="{Binding Description}" Width="230"/>
                      <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="85"/>
                      <DataGridTextColumn Header="Speed" Binding="{Binding LinkSpeed}" Width="85"/>
                      <DataGridTextColumn Header="IPv4" Binding="{Binding IPv4}" Width="120"/>
                      <DataGridTextColumn Header="Gateway" Binding="{Binding Gateway}" Width="120"/>
                      <DataGridTextColumn Header="DNS" Binding="{Binding DNS}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid></DockPanel>
                </Border>
                <GridSplitter Grid.Row="1" Style="{StaticResource HSplit}"/>
                <Border Grid.Row="2" Style="{StaticResource Card}">
                  <DockPanel><TextBlock DockPanel.Dock="Top" Text="CLOUD SERVICE CONNECTIVITY  (TCP 443)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridNetConn" RowStyle="{StaticResource RowBool}">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Target" Binding="{Binding Target}" Width="170"/>
                      <DataGridTextColumn Header="Endpoint" Binding="{Binding Endpoint}" Width="300"/>
                      <DataGridTextColumn Header="Port" Binding="{Binding Port}" Width="60"/>
                      <DataGridTextColumn Header="Reachable" Binding="{Binding Reachable}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid></DockPanel>
                </Border>
              </Grid>
            </TabItem>
          </TabControl>
        </Grid>
      </TabItem>
'@

$xamlText += @'

      <!-- CERTIFICATES -->
      <TabItem x:Name="tabCerts" Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M12,2L4,6v6c0,5,3.4,9.4,8,10c4.6-0.6,8-5,8-10V6L12,2z M10.5,15.5L7,12l1.4-1.4l2.1,2.1l5.1-5.1L17,9L10.5,15.5z"/>
            <TextBlock Text="Certificates" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="2*" MinHeight="130"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="3*" MinHeight="150"/>
          </Grid.RowDefinitions>

          <WrapPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,6">
            <Button x:Name="btnCertScan" Content="Analyse certificates"/>
            <TextBlock Text="Scope" VerticalAlignment="Center" Margin="6,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
            <ComboBox x:Name="cboCertScope" Width="110" Height="28" VerticalContentAlignment="Center" Margin="0,0,8,4">
              <ComboBoxItem Content="All" IsSelected="True"/><ComboBoxItem Content="Device"/><ComboBoxItem Content="User"/>
            </ComboBox>
            <CheckBox x:Name="chkCertCa" Content="Include root / intermediate CA stores" VerticalAlignment="Center" Margin="0,0,10,4" Foreground="{DynamicResource DxHeaderFg}"/>
            <TextBox x:Name="txtCertFind" Width="180" Height="27" VerticalContentAlignment="Center" Margin="0,0,6,4"/>
            <Button x:Name="btnCertFind" Content="Search" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnCertlm" Content="Computer certs" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnCertmgr" Content="User certs" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnCertPulse" Content="Trigger auto-enrol" Style="{StaticResource BtnWarn}"/>
          </WrapPanel>

          <UniformGrid Grid.Row="1" Rows="1" Columns="6">
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSpotBg}" BorderBrush="{DynamicResource DxSpotEdge}">
              <StackPanel><TextBlock Text="TOTAL" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSpotMuted}"/>
              <TextBlock x:Name="kpiCertTotal" Text="0" Style="{StaticResource KpiValue}" Foreground="White"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxAccentSoftBg}" BorderBrush="{DynamicResource DxAccentSoftEdge}">
              <StackPanel><TextBlock Text="DEVICE" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="kpiCertDevice" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxAccent}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevInfoBg}" BorderBrush="{DynamicResource DxSevInfoEdge2}">
              <StackPanel><TextBlock Text="USER" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="kpiCertUser" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevInfoFg}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevCritBg}" BorderBrush="{DynamicResource DxSevCritEdge}">
              <StackPanel><TextBlock Text="EXPIRED" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="kpiCertExpired" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevCritFg}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOrangeBg}" BorderBrush="{DynamicResource DxSevOrangeEdge}">
              <StackPanel><TextBlock Text="UNDER 15 DAYS" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOrangeFg}"/>
              <TextBlock x:Name="kpiCertSoon" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevOrangeFg}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOkBg2}" BorderBrush="{DynamicResource DxSevOkEdge}">
              <StackPanel><TextBlock Text="VALID" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="kpiCertValid" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevOkFg}"/></StackPanel>
            </Border>
          </UniformGrid>

          <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto" MinWidth="220"/>
              <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="180"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="EXPIRY STATUS" Style="{StaticResource CardTitle}"/>
              <StackPanel Orientation="Horizontal">
                <Canvas x:Name="cvCertStatus" Width="150" Height="150"/>
                <StackPanel x:Name="spCertLegend" VerticalAlignment="Center" Margin="10,0,0,0"/>
              </StackPanel></DockPanel>
            </Border>
            <Border Grid.Column="1" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="CERTIFICATES BY PURPOSE" Style="{StaticResource CardTitle}"/>
              <Canvas x:Name="cvCertPurpose"/></DockPanel>
            </Border>
            <GridSplitter Grid.Column="2" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="3" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="FINDINGS" Style="{StaticResource CardTitle}"/>
              <ListBox x:Name="lstCertFindings" FontSize="11.5" BorderThickness="0" HorizontalContentAlignment="Stretch">
                <ListBox.ItemTemplate><DataTemplate>
                  <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,2"/>
                </DataTemplate></ListBox.ItemTemplate>
              </ListBox></DockPanel>
            </Border>
          </Grid>

          <GridSplitter Grid.Row="3" Style="{StaticResource HSplit}"/>

          <Border Grid.Row="4" Style="{StaticResource Card}">
            <Grid>
              <Grid.RowDefinitions>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="3*" MinHeight="100"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="*" MinHeight="60"/>
              </Grid.RowDefinitions>
              <TextBlock Grid.Row="0" x:Name="lblCertSummary" Text="INVENTORY  (soonest expiry first)" Style="{StaticResource CardTitle}"/>
              <DataGrid Grid.Row="1" x:Name="gridCerts" RowStyle="{StaticResource RowCert}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="62"/>
                  <DataGridTextColumn Header="Store" Binding="{Binding Store}" Width="100"/>
                  <DataGridTextColumn Header="Subject" Binding="{Binding SubjectCN}" Width="210"/>
                  <DataGridTextColumn Header="Issuer" Binding="{Binding IssuerCN}" Width="185"/>
                  <DataGridTextColumn Header="Purpose" Binding="{Binding Purpose}" Width="195"/>
                  <DataGridTextColumn Header="Expires" Binding="{Binding NotAfter}" Width="135"/>
                  <DataGridTextColumn Header="Days" Binding="{Binding DaysLeft}" Width="55"/>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="70"/>
                  <DataGridTextColumn Header="Key" Binding="{Binding HasKey}" Width="50"/>
                  <DataGridTextColumn Header="Bits" Binding="{Binding KeySize}" Width="50"/>
                  <DataGridTextColumn Header="Thumbprint" Binding="{Binding Thumbprint}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
              <GridSplitter Grid.Row="2" Style="{StaticResource HSplit}"/>
              <Border Grid.Row="3" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="1" Background="{DynamicResource DxSubtle}" CornerRadius="8">
                <ScrollViewer VerticalScrollBarVisibility="Auto">
                  <TextBox x:Name="txtCertDetail" IsReadOnly="True" TextWrapping="Wrap" BorderThickness="0" Background="Transparent" Padding="9" FontFamily="Consolas" FontSize="11"/>
                </ScrollViewer>
              </Border>
            </Grid>
          </Border>
        </Grid>
      </TabItem>

      <!-- INTUNE MDM -->
      <TabItem Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M7,2h10c1.1,0,2,0.9,2,2v16c0,1.1-0.9,2-2,2H7c-1.1,0-2-0.9-2-2V4C5,2.9,5.9,2,7,2z M7,5v13h10V5H7z M12,19.2c0.6,0,1,0.4,1,1s-0.4,1-1,1s-1-0.4-1-1S11.4,19.2,12,19.2z"/>
            <TextBlock Text="Intune / MDM" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="2*" MinHeight="120"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="3*" MinHeight="160"/>
          </Grid.RowDefinitions>

          <WrapPanel Grid.Row="0" Margin="0,0,0,6">
            <Button x:Name="btnIntuneScan" Content="Analyse Intune / MDM"/>
            <Button x:Name="btnIntuneDeep" Content="Deep diagnostics" Style="{StaticResource BtnOk}"/>
            <Button x:Name="btnEndpointTest" Content="Test service endpoints" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnIntuneSync" Content="Force MDM sync" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnImeRestart" Content="Restart IME service" Style="{StaticResource BtnWarn}"/>
            <Button x:Name="btnMdmDiag" Content="Collect MDM bundle" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnOpenImeLogs" Content="Open IME logs" Style="{StaticResource BtnGhost}"/>
            <TextBlock x:Name="lblIntuneSummary" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/>
          </WrapPanel>

          <UniformGrid Grid.Row="1" Rows="1" Columns="6" Margin="0,0,0,2">
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSpotBg}" BorderBrush="{DynamicResource DxSpotEdge}">
              <StackPanel><TextBlock Text="MANAGEMENT HEALTH" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSpotMuted}"/>
              <TextBlock x:Name="kpiIntuneScore" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSpotFg}"/>
              <TextBlock x:Name="lblIntuneVerdict" Text="not checked" FontSize="10" Foreground="{DynamicResource DxSpotMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevWarnBg2}" BorderBrush="{DynamicResource DxSevWarnEdge}">
              <StackPanel><TextBlock Text="LAST GOOD SYNC" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevWarnFg}"/>
              <TextBlock x:Name="kpiSyncAge" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevWarnFg}"/>
              <TextBlock x:Name="lblSyncNote" Text="hours ago" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevInfoBg2}" BorderBrush="{DynamicResource DxSevInfoEdge}">
              <StackPanel><TextBlock Text="MDM CERTIFICATE" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="kpiMdmCert" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="lblMdmCertNote" Text="days remaining" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOkBg2}" BorderBrush="{DynamicResource DxSevOkEdge}">
              <StackPanel><TextBlock Text="SERVICE ENDPOINTS" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="kpiEndpoints" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="lblEndpointsNote" Text="not tested" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevCritBg}" BorderBrush="{DynamicResource DxSevCritEdge}">
              <StackPanel><TextBlock Text="APPS FAILING" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="kpiAppsFailed" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="lblAppsNote" Text="Win32 + MSI/LOB" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxAccentSoftBg}" BorderBrush="{DynamicResource DxAccentSoftEdge}">
              <StackPanel><TextBlock Text="SCRIPTS FAILING" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="kpiScriptsFailed" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="lblScriptsNote" Text="scripts + remediations" FontSize="10" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/></StackPanel>
            </Border>
          </UniformGrid>

          <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" MinWidth="220"/><ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="200"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="ENROLMENT AND IDENTITY" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridIntune">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Property" Binding="{Binding Property}" Width="190"/>
                  <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
            <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="2" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="FINDINGS" Style="{StaticResource CardTitle}"/>
              <ListBox x:Name="lstIntuneIssues" FontSize="11.5" BorderThickness="0" HorizontalContentAlignment="Stretch">
                <ListBox.ItemTemplate>
                  <DataTemplate><TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,2"/></DataTemplate>
                </ListBox.ItemTemplate>
              </ListBox></DockPanel>
            </Border>
          </Grid>

          <GridSplitter Grid.Row="3" Style="{StaticResource HSplit}"/>

          <TabControl Grid.Row="4" Margin="5" Background="{DynamicResource DxTabStripBg}" BorderBrush="{DynamicResource DxCardBorder}">
            <TabItem Header="Sync health">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <TextBlock Grid.Row="0" x:Name="lblSyncSummary" Margin="2,0,0,6" TextWrapping="Wrap" Foreground="{DynamicResource DxMuted}"/>
                <DataGrid Grid.Row="1" x:Name="gridSyncSessions" RowStyle="{StaticResource RowLevel}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                    <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="52"/>
                    <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="80"/>
                    <DataGridTextColumn Header="Session" Binding="{Binding Kind}" Width="190"/>
                    <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            <TabItem Header="Service endpoints">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <DataGrid Grid.Row="0" x:Name="gridEndpoints" RowStyle="{StaticResource RowSeverity}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Endpoint" Binding="{Binding Endpoint}" Width="250"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="70"/>
                    <DataGridTextColumn Header="Latency ms" Binding="{Binding LatencyMs}" Width="90"/>
                    <DataGridTextColumn Header="Purpose" Binding="{Binding Purpose}" Width="290"/>
                    <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
                <TextBlock Grid.Row="1" x:Name="lblProxy" Margin="2,6,0,0" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11" Foreground="{DynamicResource DxMuted}"/>
              </Grid>
            </TabItem>
            <TabItem Header="Certificates">
              <DataGrid x:Name="gridMdmCerts" Margin="4" RowStyle="{StaticResource RowSeverity}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Role" Binding="{Binding Role}" Width="270"/>
                  <DataGridTextColumn Header="State" Binding="{Binding State}" Width="100"/>
                  <DataGridTextColumn Header="Days left" Binding="{Binding DaysLeft}" Width="76"/>
                  <DataGridTextColumn Header="Expires" Binding="{Binding NotAfter}" Width="150"/>
                  <DataGridTextColumn Header="Key" Binding="{Binding HasPrivateKey}" Width="50"/>
                  <DataGridTextColumn Header="Subject" Binding="{Binding Subject}" Width="250"/>
                  <DataGridTextColumn Header="Thumbprint" Binding="{Binding Thumbprint}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Win32 apps">
              <DockPanel Margin="4">
                <TextBlock x:Name="lblWin32" DockPanel.Dock="Top" Text="WIN32 APP ENFORCEMENT STATE" Style="{StaticResource CardTitle}"/>
                <DataGrid x:Name="gridWin32" RowStyle="{StaticResource RowApp}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="150"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="170"/>
                    <DataGridTextColumn Header="Error" Binding="{Binding ErrorCode}" Width="90"/>
                    <DataGridTextColumn Header="Targeting" Binding="{Binding Targeting}" Width="90"/>
                    <DataGridTextColumn Header="Complete" Binding="{Binding Complete}" Width="72"/>
                    <DataGridTextColumn Header="App ID" Binding="{Binding AppId}" Width="270"/>
                    <DataGridTextColumn Header="Values found" Binding="{Binding ValueNames}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </TabItem>
            <TabItem Header="MSI / LOB apps">
              <DockPanel Margin="4">
                <TextBlock x:Name="lblMsiApps" DockPanel.Dock="Top" Text="MSI AND LINE-OF-BUSINESS APPS  (EnterpriseDesktopAppManagement - a different path from Win32)" Style="{StaticResource CardTitle}"/>
                <DataGrid x:Name="gridMsiApps" RowStyle="{StaticResource RowApp}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="150"/>
                    <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="140"/>
                    <DataGridTextColumn Header="Last error" Binding="{Binding LastError}" Width="100"/>
                    <DataGridTextColumn Header="Version" Binding="{Binding Version}" Width="110"/>
                    <DataGridTextColumn Header="Downloads" Binding="{Binding DownloadCount}" Width="80"/>
                    <DataGridTextColumn Header="Product code" Binding="{Binding ProductCode}" Width="260"/>
                    <DataGridTextColumn Header="Values found" Binding="{Binding ValueNames}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </TabItem>
            <TabItem Header="PowerShell scripts">
              <DockPanel Margin="4">
                <TextBlock x:Name="lblPsScripts" DockPanel.Dock="Top" Text="PLATFORM POWERSHELL SCRIPTS" Style="{StaticResource CardTitle}"/>
                <DataGrid x:Name="gridPsScripts" RowStyle="{StaticResource RowScript}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="160"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="110"/>
                    <DataGridTextColumn Header="Error" Binding="{Binding ErrorCode}" Width="90"/>
                    <DataGridTextColumn Header="DL" Binding="{Binding Downloads}" Width="52"/>
                    <DataGridTextColumn Header="Script ID" Binding="{Binding ScriptId}" Width="250"/>
                    <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </TabItem>
            <TabItem Header="Remediations">
              <DockPanel Margin="4">
                <TextBlock x:Name="lblRemediations" DockPanel.Dock="Top" Text="REMEDIATIONS  (proactive remediations / health scripts)" Style="{StaticResource CardTitle}"/>
                <DataGrid x:Name="gridRemediations" RowStyle="{StaticResource RowScript}">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="160"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="110"/>
                    <DataGridTextColumn Header="Error" Binding="{Binding ErrorCode}" Width="90"/>
                    <DataGridTextColumn Header="Last run" Binding="{Binding LastRun}" Width="150"/>
                    <DataGridTextColumn Header="Runs" Binding="{Binding Executions}" Width="56"/>
                    <DataGridTextColumn Header="Script ID" Binding="{Binding ScriptId}" Width="230"/>
                    <DataGridTextColumn Header="Detection output" Binding="{Binding Detail}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </TabItem>
            <TabItem Header="Autopilot and ESP">
              <Grid Margin="4">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*" MinWidth="240"/><ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*" MinWidth="260"/>
                </Grid.ColumnDefinitions>
                <DockPanel Grid.Column="0">
                  <TextBlock DockPanel.Dock="Top" Text="PROVISIONING STATE" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridAutopilot">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="230"/>
                      <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="180"/>
                      <DataGridTextColumn Header="Note" Binding="{Binding Note}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                <DockPanel Grid.Column="2">
                  <TextBlock DockPanel.Dock="Top" Text="PROVISIONING EVENTS" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridApEvents" RowStyle="{StaticResource RowLevel}">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                      <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="52"/>
                      <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="80"/>
                      <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>
            </TabItem>
            <TabItem Header="MDM sync tasks">
              <DataGrid x:Name="gridMdmTasks" Margin="4">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Task" Binding="{Binding TaskName}" Width="320"/>
                  <DataGridTextColumn Header="State" Binding="{Binding State}" Width="90"/>
                  <DataGridTextColumn Header="Last run" Binding="{Binding LastRunTime}" Width="160"/>
                  <DataGridTextColumn Header="Result" Binding="{Binding LastResult}" Width="90"/>
                  <DataGridTextColumn Header="Next run" Binding="{Binding NextRunTime}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="MDM channel events">
              <DataGrid x:Name="gridMdmEvents" Margin="4" RowStyle="{StaticResource RowLevel}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Time" Binding="{Binding TimeCreated}" Width="150"/>
                  <DataGridTextColumn Header="Level" Binding="{Binding LevelDisplayName}" Width="80"/>
                  <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="56"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="IME log findings">
              <DataGrid x:Name="gridImeLogs" Margin="4" RowStyle="{StaticResource RowSeverity}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                  <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="80"/>
                  <DataGridTextColumn Header="Log file" Binding="{Binding LogFile}" Width="200"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Activity timeline">
              <DockPanel Margin="4">
                <TextBlock DockPanel.Dock="Top" Text="EVERY MDM SIGNAL, NEWEST FIRST  (enrolment, channel, sync sessions, task runs, provisioning)" Style="{StaticResource CardTitle}"/>
                <DataGrid x:Name="gridTimeline">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                    <DataGridTextColumn Header="Source" Binding="{Binding Source}" Width="110"/>
                    <DataGridTextColumn Header="Signal" Binding="{Binding Signal}" Width="260"/>
                    <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </TabItem>
          </TabControl>
        </Grid>
      </TabItem>

      <!-- GROUP POLICY -->
      <!-- POLICY  (Policy CSP + Group Policy merged) -->
      <TabItem x:Name="tabPolicy" Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M12,1L3,5v6c0,5.6,3.8,10.7,9,12c5.2-1.3,9-6.4,9-12V5L12,1z M12,6c1.7,0,3,1.3,3,3s-1.3,3-3,3s-3-1.3-3-3S10.3,6,12,6z M12,13c2,0,6,1,6,3v1H6v-1C6,14,10,13,12,13z"/>
            <TextBlock Text="Policy" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*" MinHeight="200"/>
          </Grid.RowDefinitions>

          <WrapPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,6">
            <Button x:Name="btnPolicyScan" Content="Analyse policy"/>
            <Button x:Name="btnGpoScan" Content="Analyse Group Policy" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnGpUpdate" Content="gpupdate /force" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnGpHtml" Content="Open full RSoP report" Style="{StaticResource BtnGhost}"/>
            <TextBlock Text="Search" VerticalAlignment="Center" Margin="6,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
            <TextBox x:Name="txtPolicyFind" Width="230" Height="27" VerticalContentAlignment="Center" Margin="0,0,6,4"/>
            <Button x:Name="btnPolicyFind" Content="Search" Style="{StaticResource BtnGhost}"/>
            <Button x:Name="btnPolicyClear" Content="Clear" Style="{StaticResource BtnGhost}"/>
            <CheckBox x:Name="chkPolicyAdmx" Content="Show ADMX metadata rows" VerticalAlignment="Center" Margin="6,0,10,4" Foreground="{DynamicResource DxInk}"/>
            <Button x:Name="btnPolicyCsv" Content="Export CSV" Style="{StaticResource BtnOk}"/>
            <TextBlock x:Name="lblPolicySummary" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/>
            <TextBlock x:Name="lblGpoSummary" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/>
          </WrapPanel>

          <UniformGrid Grid.Row="1" Rows="1" Columns="5">
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxAccentSoftBg}" BorderBrush="{DynamicResource DxAccentSoftEdge}">
              <StackPanel><TextBlock Text="POLICY CSP SETTINGS" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="kpiPolMdm" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock Text="from Intune profiles" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevInfoBg2}" BorderBrush="{DynamicResource DxSevInfoEdge}">
              <StackPanel><TextBlock Text="POLICY AREAS" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="kpiPolAreas" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock Text="CSP namespaces" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOkBg2}" BorderBrush="{DynamicResource DxSevOkEdge}">
              <StackPanel><TextBlock Text="GROUP POLICY" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="kpiPolGpo" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="lblPolGpoNote" Text="from RSoP" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevWarnBg2}" BorderBrush="{DynamicResource DxSevWarnEdge}">
              <StackPanel><TextBlock Text="REGISTRY POLICY" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevWarnFg}"/>
              <TextBlock x:Name="kpiPolReg" Text="0" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevWarnFg}"/>
              <TextBlock Text="legacy / local" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSpotBg}" BorderBrush="{DynamicResource DxSpotEdge}">
              <StackPanel><TextBlock Text="WHO WINS" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSpotMuted}"/>
              <TextBlock x:Name="kpiPolWins" Text="--" FontSize="17" FontWeight="Bold" Foreground="White" Margin="0,6,0,0"/>
              <TextBlock x:Name="lblPolWinsNote" Text="MDMWinsOverGP" FontSize="10" Foreground="{DynamicResource DxSpotMuted}"/></StackPanel>
            </Border>
          </UniformGrid>

          <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="Auto" MinWidth="210"/>
              <ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="360"/>
            </Grid.ColumnDefinitions>

            <Border Grid.Column="0" Style="{StaticResource Card}" Width="270">
              <DockPanel>
                <TextBlock DockPanel.Dock="Top" Text="POLICY AREAS  (click to filter)" Style="{StaticResource CardTitle}"/>
                <Button DockPanel.Dock="Bottom" x:Name="btnPolicyAllAreas" Content="Show all areas" Style="{StaticResource BtnMini}" Margin="0,6,0,0"/>
                <DataGrid x:Name="gridPolicyAreas">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Area" Binding="{Binding Area}" Width="*"/>
                    <DataGridTextColumn Header="No." Binding="{Binding Count}" Width="46"/>
                  </DataGrid.Columns>
                </DataGrid>
              </DockPanel>
            </Border>

            <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>

            <TabControl Grid.Column="2" x:Name="policySubTabs" Margin="5">
              <TabItem Header="Effective settings">
                <DockPanel Margin="4">
                  <TextBlock DockPanel.Dock="Top" x:Name="lblPolicyRows" Text="POLICY CSP" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridPolicyMdm">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="80"/>
                      <DataGridTextColumn Header="Area" Binding="{Binding AreaName}" Width="170"/>
                      <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="240"/>
                      <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="140"/>
                      <DataGridTextColumn Header="Set by" Binding="{Binding Owner}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </TabItem>
              <TabItem Header="Registry policy">
                <DockPanel Margin="4">
                  <TextBlock DockPanel.Dock="Top" x:Name="lblPolicyRegRows" Text="REGISTRY POLICY" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridPolicyReg">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="95"/>
                      <DataGridTextColumn Header="Key" Binding="{Binding Area}" Width="180"/>
                      <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="210"/>
                      <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="130"/>
                      <DataGridTextColumn Header="Path" Binding="{Binding KeyPath}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </TabItem>
              <TabItem Header="Group Policy">
                <DockPanel Margin="4">
                  <TextBlock DockPanel.Dock="Top" x:Name="lblPolicyGpoRows" Text="GROUP POLICY SETTINGS" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridPolicyGpo">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="70"/>
                      <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="250"/>
                      <DataGridTextColumn Header="State" Binding="{Binding State}" Width="80"/>
                      <DataGridTextColumn Header="Key" Binding="{Binding KeyName}" Width="260"/>
                      <DataGridTextColumn Header="Winning GPO" Binding="{Binding GPO}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </TabItem>
              <TabItem Header="Overlaps">
                <DockPanel Margin="4">
                  <TextBlock DockPanel.Dock="Top" Text="SETTINGS CONFIGURED BY BOTH POLICY CSP AND GROUP POLICY  (name match is a hint - verify the key)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridPolicyConflicts" RowStyle="{StaticResource RowSeverity}">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="220"/>
                      <DataGridTextColumn Header="Area" Binding="{Binding Area}" Width="150"/>
                      <DataGridTextColumn Header="MDM value" Binding="{Binding MdmValue}" Width="110"/>
                      <DataGridTextColumn Header="GPO value" Binding="{Binding GpoValue}" Width="110"/>
                      <DataGridTextColumn Header="Winner" Binding="{Binding Winner}" Width="120"/>
                      <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </TabItem>
              <TabItem Header="Findings">
                <DockPanel Margin="4">
                  <TextBlock DockPanel.Dock="Top" Text="FINDINGS" Style="{StaticResource CardTitle}"/>
                  <ListBox x:Name="lstPolicyFindings" FontSize="11.5" BorderThickness="0" HorizontalContentAlignment="Stretch">
                    <ListBox.ItemTemplate><DataTemplate>
                      <TextBlock Text="{Binding}" TextWrapping="Wrap" Margin="0,2"/>
                    </DataTemplate></ListBox.ItemTemplate>
                  </ListBox>
                </DockPanel>
              </TabItem>
            <TabItem Header="GP conflicts">
              <DataGrid x:Name="gridConflicts" Margin="4" RowStyle="{StaticResource RowSeverity}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Severity" Binding="{Binding Severity}" Width="76"/>
                  <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="140"/>
                  <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="76"/>
                  <DataGridTextColumn Header="Subject" Binding="{Binding Subject}" Width="290"/>
                  <DataGridTextColumn Header="Winner" Binding="{Binding Winner}" Width="165"/>
                  <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Applied GPOs">
              <Grid Margin="4">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*" MinWidth="220"/><ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*" MinWidth="220"/>
                </Grid.ColumnDefinitions>
                <DockPanel Grid.Column="0">
                  <TextBlock DockPanel.Dock="Top" Text="APPLIED GPOS  (precedence order)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridGpoApplied">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="66"/>
                      <DataGridTextColumn Header="Order" Binding="{Binding Order}" Width="52"/>
                      <DataGridTextColumn Header="GPO" Binding="{Binding Name}" Width="230"/>
                      <DataGridTextColumn Header="Enforced" Binding="{Binding Enforced}" Width="68"/>
                      <DataGridTextColumn Header="Linked at" Binding="{Binding Link}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                <DockPanel Grid.Column="2">
                  <TextBlock DockPanel.Dock="Top" Text="FILTERED / DENIED GPOS" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridGpoDenied" RowStyle="{StaticResource RowWarnAll}">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="66"/>
                      <DataGridTextColumn Header="GPO" Binding="{Binding Name}" Width="230"/>
                      <DataGridTextColumn Header="Enabled" Binding="{Binding Enabled}" Width="68"/>
                      <DataGridTextColumn Header="Denied" Binding="{Binding AccessDenied}" Width="68"/>
                      <DataGridTextColumn Header="Filter OK" Binding="{Binding FilterAllowed}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>
            </TabItem>
            <TabItem Header="GP extension status">
              <DataGrid x:Name="gridCse" Margin="4" RowStyle="{StaticResource RowCse}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="66"/>
                  <DataGridTextColumn Header="GPO" Binding="{Binding GPO}" Width="250"/>
                  <DataGridTextColumn Header="Extension" Binding="{Binding Extension}" Width="235"/>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="90"/>
                  <DataGridTextColumn Header="Begin" Binding="{Binding BeginTime}" Width="165"/>
                  <DataGridTextColumn Header="End" Binding="{Binding EndTime}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="GP events">
              <DataGrid x:Name="gridGpEvents" Margin="4" RowStyle="{StaticResource RowLevel}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Time" Binding="{Binding TimeCreated}" Width="140"/>
                  <DataGridTextColumn Header="Level" Binding="{Binding Level}" Width="70"/>
                  <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="56"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="GP precedence map">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,6">
                  <TextBlock Text="Search setting / key / GPO" VerticalAlignment="Center" Margin="0,0,6,0" Foreground="{DynamicResource DxMuted}" FontWeight="SemiBold"/>
                  <TextBox x:Name="txtGpoFind" Width="290" Height="27" VerticalContentAlignment="Center" Margin="0,0,8,0"/>
                  <Button x:Name="btnGpoFind" Content="Search"/>
                  <TextBlock x:Name="lblGpoRows" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{DynamicResource DxMuted}"/>
                </StackPanel>
                <DataGrid Grid.Row="1" x:Name="gridGpoSettings">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Scope" Binding="{Binding Scope}" Width="66"/>
                    <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="270"/>
                    <DataGridTextColumn Header="State" Binding="{Binding State}" Width="76"/>
                    <DataGridTextColumn Header="Key" Binding="{Binding KeyName}" Width="290"/>
                    <DataGridTextColumn Header="Value name" Binding="{Binding ValueName}" Width="145"/>
                    <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="80"/>
                    <DataGridTextColumn Header="Winning GPO" Binding="{Binding GPO}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            </TabControl>
          </Grid>
        </Grid>
      </TabItem>

      <!-- SYSTEM HEALTH -->
      <TabItem Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M20.6,3.4C19.4,2.2,17.8,1.5,16,1.5c-1.6,0-3.1,0.6-4,1.6c-0.9-1-2.4-1.6-4-1.6c-1.8,0-3.4,0.7-4.6,1.9C2.2,4.6,1.5,6.2,1.5,8c0,4.6,4.5,8.7,10.5,14.5C18,16.7,22.5,12.6,22.5,8C22.5,6.2,21.8,4.6,20.6,3.4z"/>
            <TextBlock Text="System Health" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <Grid Margin="8">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*" MinHeight="110"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*" MinHeight="110"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="2*" MinHeight="140"/>
          </Grid.RowDefinitions>

          <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,6">
            <Button x:Name="btnSysScan" Content="Run system diagnostics"/>
            <Button x:Name="btnAdvScan" Content="Run hardware and posture checks" Style="{StaticResource BtnOk}"/>
            <TextBlock x:Name="lblAdvSummary" VerticalAlignment="Center" Margin="10,0,10,0" Foreground="{DynamicResource DxMuted}" TextTrimming="CharacterEllipsis"/>
            <TextBlock x:Name="lblRebootPending" VerticalAlignment="Center" Margin="10,0,0,0" Foreground="{DynamicResource DxSevWarnFg}" FontWeight="SemiBold" TextTrimming="CharacterEllipsis"/>
          </StackPanel>


          <UniformGrid Grid.Row="1" Rows="1" Columns="6" Margin="0,0,0,2">
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSpotBg}" BorderBrush="{DynamicResource DxSpotEdge}">
              <StackPanel><TextBlock Text="BATTERY WEAR" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSpotMuted}"/>
              <TextBlock x:Name="kpiBattWear" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSpotFg}"/>
              <TextBlock x:Name="lblBattNote" Text="not checked" FontSize="10" Foreground="{DynamicResource DxSpotMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevInfoBg2}" BorderBrush="{DynamicResource DxSevInfoEdge}">
              <StackPanel><TextBlock Text="DISK WEAR" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="kpiDiskWear" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevInfoFg}"/>
              <TextBlock x:Name="lblDiskNote" Text="not checked" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevOkBg2}" BorderBrush="{DynamicResource DxSevOkEdge}">
              <StackPanel><TextBlock Text="BOOT INTEGRITY" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevOkFg}"/>
              <TextBlock x:Name="kpiSecureBoot" Text="--" FontSize="17" FontWeight="SemiBold" Foreground="{DynamicResource DxSevOkFg}" Margin="0,6,0,0"/>
              <TextBlock x:Name="lblTpmNote" Text="Secure Boot / TPM" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxAccentSoftBg}" BorderBrush="{DynamicResource DxAccentSoftEdge}">
              <StackPanel><TextBlock Text="VBS / HVCI" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxAccent}"/>
              <TextBlock x:Name="kpiVbs" Text="--" FontSize="17" FontWeight="SemiBold" Foreground="{DynamicResource DxAccent}" Margin="0,6,0,0"/>
              <TextBlock x:Name="lblVbsNote" Text="memory integrity" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevWarnBg2}" BorderBrush="{DynamicResource DxSevWarnEdge}">
              <StackPanel><TextBlock Text="ENCRYPTION" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevWarnFg}"/>
              <TextBlock x:Name="kpiBitlocker" Text="--" FontSize="17" FontWeight="SemiBold" Foreground="{DynamicResource DxSevWarnFg}" Margin="0,6,0,0"/>
              <TextBlock x:Name="lblBlNote" Text="BitLocker, OS volume" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
            <Border Style="{StaticResource Card}" Background="{DynamicResource DxSevCritBg}" BorderBrush="{DynamicResource DxSevCritEdge}">
              <StackPanel><TextBlock Text="UPTIME" Style="{StaticResource KpiLabel}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="kpiUptimeDays" Text="--" Style="{StaticResource KpiValue}" Foreground="{DynamicResource DxSevCritFg}"/>
              <TextBlock x:Name="lblUncleanNote" Text="unclean shutdowns" FontSize="10" Foreground="{DynamicResource DxMuted}"/></StackPanel>
            </Border>
          </UniformGrid>
          <Grid Grid.Row="2">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="180"/><ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="180"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="DISK USAGE" Style="{StaticResource CardTitle}"/>
              <Canvas x:Name="cvDisks"/></DockPanel>
            </Border>
            <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="2" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="VOLUMES" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridDisks">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Drive" Binding="{Binding Drive}" Width="52"/>
                  <DataGridTextColumn Header="Label" Binding="{Binding Label}" Width="110"/>
                  <DataGridTextColumn Header="Size GB" Binding="{Binding SizeGB}" Width="70"/>
                  <DataGridTextColumn Header="Free GB" Binding="{Binding FreeGB}" Width="70"/>
                  <DataGridTextColumn Header="Free %" Binding="{Binding FreePct}" Width="62"/>
                  <DataGridTextColumn Header="Health" Binding="{Binding Health}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
            <GridSplitter Grid.Column="3" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="4" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="CLOUD CONNECTIVITY  (TCP 443)" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridConn" RowStyle="{StaticResource RowBool}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Target" Binding="{Binding Target}" Width="140"/>
                  <DataGridTextColumn Header="Endpoint" Binding="{Binding Endpoint}" Width="*"/>
                  <DataGridTextColumn Header="OK" Binding="{Binding Reachable}" Width="70"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
          </Grid>

          <GridSplitter Grid.Row="3" Style="{StaticResource HSplit}"/>

          <Grid Grid.Row="4">
            <Grid.ColumnDefinitions>
              <ColumnDefinition Width="*" MinWidth="200"/><ColumnDefinition Width="Auto"/>
              <ColumnDefinition Width="*" MinWidth="200"/>
            </Grid.ColumnDefinitions>
            <Border Grid.Column="0" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="DEVICES REPORTING A PROBLEM" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridDevices" RowStyle="{StaticResource RowErrAll}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Device" Binding="{Binding Device}" Width="250"/>
                  <DataGridTextColumn Header="Class" Binding="{Binding Class}" Width="105"/>
                  <DataGridTextColumn Header="Code" Binding="{Binding ErrorCode}" Width="52"/>
                  <DataGridTextColumn Header="Meaning" Binding="{Binding Meaning}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
            <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
            <Border Grid.Column="2" Style="{StaticResource Card}">
              <DockPanel><TextBlock DockPanel.Dock="Top" Text="AUTOMATIC SERVICES NOT RUNNING" Style="{StaticResource CardTitle}"/>
              <DataGrid x:Name="gridServices" RowStyle="{StaticResource RowWarnAll}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Service" Binding="{Binding Name}" Width="185"/>
                  <DataGridTextColumn Header="Display name" Binding="{Binding DisplayName}" Width="*"/>
                  <DataGridTextColumn Header="State" Binding="{Binding State}" Width="85"/>
                </DataGrid.Columns>
              </DataGrid></DockPanel>
            </Border>
          </Grid>

          <GridSplitter Grid.Row="5" Style="{StaticResource HSplit}"/>

          <TabControl Grid.Row="6" Background="{DynamicResource DxCardBg}" BorderBrush="{DynamicResource DxCardBorder}" Margin="5">
            <TabItem Header="Stability">
              <DataGrid x:Name="gridStability" Margin="4" RowStyle="{StaticResource RowErrAll}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="140"/>
                  <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="52"/>
                  <DataGridTextColumn Header="Provider" Binding="{Binding Provider}" Width="160"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Crashes and hangs">
              <DataGrid x:Name="gridCrashes" Margin="4" RowStyle="{StaticResource RowErrAll}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="140"/>
                  <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="60"/>
                  <DataGridTextColumn Header="App" Binding="{Binding App}" Width="180"/>
                  <DataGridTextColumn Header="Module" Binding="{Binding Module}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Recent updates">
              <DataGrid x:Name="gridUpdates" Margin="4">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="KB" Binding="{Binding HotFixID}" Width="110"/>
                  <DataGridTextColumn Header="Type" Binding="{Binding Description}" Width="120"/>
                  <DataGridTextColumn Header="Installed" Binding="{Binding InstalledOn}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Windows Update errors">
              <DataGrid x:Name="gridWuErrors" Margin="4" RowStyle="{StaticResource RowLevel}">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="140"/>
                  <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="52"/>
                  <DataGridTextColumn Header="Message" Binding="{Binding Message}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
                      <TabItem Header="Advanced findings">
              <DataGrid x:Name="gridAdvFindings" Margin="4">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Finding" Binding="{Binding}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Battery">
              <DataGrid x:Name="gridBattery" Margin="4">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Battery" Binding="{Binding Name}" Width="130"/>
                  <DataGridTextColumn Header="Health" Binding="{Binding Health}" Width="200"/>
                  <DataGridTextColumn Header="Wear %" Binding="{Binding WearPct}" Width="66"/>
                  <DataGridTextColumn Header="Cycles" Binding="{Binding CycleCount}" Width="62"/>
                  <DataGridTextColumn Header="Design mWh" Binding="{Binding DesignedmWh}" Width="88"/>
                  <DataGridTextColumn Header="Full mWh" Binding="{Binding FullChargemWh}" Width="82"/>
                  <DataGridTextColumn Header="Charge %" Binding="{Binding ChargePct}" Width="74"/>
                  <DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="120"/>
                  <DataGridTextColumn Header="Chemistry" Binding="{Binding Chemistry}" Width="76"/>
                  <DataGridTextColumn Header="Manufacturer" Binding="{Binding Manufacturer}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Storage health">
              <DataGrid x:Name="gridStorageHealth" Margin="4">
                <DataGrid.Columns>
                  <DataGridTextColumn Header="Model" Binding="{Binding Model}" Width="230"/>
                  <DataGridTextColumn Header="Media" Binding="{Binding Media}" Width="66"/>
                  <DataGridTextColumn Header="Bus" Binding="{Binding Bus}" Width="58"/>
                  <DataGridTextColumn Header="Size GB" Binding="{Binding SizeGB}" Width="70"/>
                  <DataGridTextColumn Header="Health" Binding="{Binding Health}" Width="72"/>
                  <DataGridTextColumn Header="Wear %" Binding="{Binding WearPct}" Width="64"/>
                  <DataGridTextColumn Header="Temp C" Binding="{Binding TempC}" Width="62"/>
                  <DataGridTextColumn Header="Max C" Binding="{Binding TempMaxC}" Width="58"/>
                  <DataGridTextColumn Header="On hours" Binding="{Binding PowerOnHours}" Width="74"/>
                  <DataGridTextColumn Header="Realloc" Binding="{Binding ReallocatedSectors}" Width="66"/>
                  <DataGridTextColumn Header="Rd err" Binding="{Binding ReadErrors}" Width="60"/>
                  <DataGridTextColumn Header="Wr err" Binding="{Binding WriteErrors}" Width="60"/>
                  <DataGridTextColumn Header="Verdict" Binding="{Binding Verdict}" Width="*"/>
                </DataGrid.Columns>
              </DataGrid>
            </TabItem>
            <TabItem Header="Security posture">
              <Grid Margin="4">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*" MinWidth="260"/><ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*" MinWidth="240"/>
                </Grid.ColumnDefinitions>
                <DockPanel Grid.Column="0">
                  <TextBlock DockPanel.Dock="Top" Text="POSTURE  (what is actually on, not what policy intends)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridPosture" RowStyle="{StaticResource RowSeverity}">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Area" Binding="{Binding Area}" Width="86"/>
                      <DataGridTextColumn Header="Setting" Binding="{Binding Setting}" Width="200"/>
                      <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="150"/>
                      <DataGridTextColumn Header="Expected" Binding="{Binding Expected}" Width="90"/>
                      <DataGridTextColumn Header="State" Binding="{Binding State}" Width="66"/>
                      <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                <DockPanel Grid.Column="2">
                  <TextBlock DockPanel.Dock="Top" Text="BITLOCKER VOLUMES" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridBitlocker">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Mount" Binding="{Binding Mount}" Width="62"/>
                      <DataGridTextColumn Header="Type" Binding="{Binding VolumeType}" Width="106"/>
                      <DataGridTextColumn Header="Protection" Binding="{Binding Protection}" Width="80"/>
                      <DataGridTextColumn Header="Method" Binding="{Binding Encryption}" Width="120"/>
                      <DataGridTextColumn Header="%" Binding="{Binding Percent}" Width="46"/>
                      <DataGridTextColumn Header="Key protectors" Binding="{Binding KeyProtectors}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>
            </TabItem>
            <TabItem Header="Memory">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
                <TextBlock Grid.Row="0" x:Name="lblMemSummary" Margin="2,0,0,6" Foreground="{DynamicResource DxMuted}" TextWrapping="Wrap"/>
                <DataGrid Grid.Row="1" x:Name="gridMemory">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Slot" Binding="{Binding Slot}" Width="120"/>
                    <DataGridTextColumn Header="Bank" Binding="{Binding Bank}" Width="92"/>
                    <DataGridTextColumn Header="GB" Binding="{Binding CapacityGB}" Width="56"/>
                    <DataGridTextColumn Header="Type" Binding="{Binding Type}" Width="66"/>
                    <DataGridTextColumn Header="Form" Binding="{Binding Form}" Width="72"/>
                    <DataGridTextColumn Header="Rated MHz" Binding="{Binding SpeedMHz}" Width="82"/>
                    <DataGridTextColumn Header="Actual MHz" Binding="{Binding ConfiguredMHz}" Width="86"/>
                    <DataGridTextColumn Header="Manufacturer" Binding="{Binding Manufacturer}" Width="130"/>
                    <DataGridTextColumn Header="Part number" Binding="{Binding PartNumber}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
                <TextBlock Grid.Row="2" Text="PAGE FILES" Style="{StaticResource CardTitle}" Margin="2,8,0,2"/>
                <DataGrid Grid.Row="3" x:Name="gridPageFiles" MaxHeight="120">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Path" Binding="{Binding Name}" Width="300"/>
                    <DataGridTextColumn Header="Allocated MB" Binding="{Binding AllocatedMB}" Width="110"/>
                    <DataGridTextColumn Header="Current MB" Binding="{Binding CurrentMB}" Width="100"/>
                    <DataGridTextColumn Header="Peak MB" Binding="{Binding PeakMB}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            <TabItem Header="Top processes">
              <Grid Margin="4">
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*" MinWidth="240"/><ColumnDefinition Width="Auto"/>
                  <ColumnDefinition Width="*" MinWidth="240"/>
                </Grid.ColumnDefinitions>
                <DockPanel Grid.Column="0">
                  <TextBlock DockPanel.Dock="Top" Text="BY MEMORY  (working set)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridProcMem">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Process" Binding="{Binding Name}" Width="170"/>
                      <DataGridTextColumn Header="PID" Binding="{Binding Id}" Width="62"/>
                      <DataGridTextColumn Header="WS MB" Binding="{Binding WorkingSetMB}" Width="76"/>
                      <DataGridTextColumn Header="Private MB" Binding="{Binding PrivateMB}" Width="86"/>
                      <DataGridTextColumn Header="Handles" Binding="{Binding Handles}" Width="70"/>
                      <DataGridTextColumn Header="Threads" Binding="{Binding Threads}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
                <DockPanel Grid.Column="2">
                  <TextBlock DockPanel.Dock="Top" Text="BY CPU  (sampled over one second)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridProcCpu">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Process" Binding="{Binding Name}" Width="170"/>
                      <DataGridTextColumn Header="PID" Binding="{Binding Id}" Width="62"/>
                      <DataGridTextColumn Header="CPU %" Binding="{Binding CpuPct}" Width="70"/>
                      <DataGridTextColumn Header="WS MB" Binding="{Binding WorkingSetMB}" Width="76"/>
                      <DataGridTextColumn Header="Started" Binding="{Binding Started}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>
            </TabItem>
            <TabItem Header="Drivers">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,6">
                  <Button x:Name="btnDrvAll" Content="All drivers" Style="{StaticResource BtnMini}"/>
                  <Button x:Name="btnDrvKey" Content="Key classes" Style="{StaticResource BtnMini}"/>
                  <Button x:Name="btnDrvStale" Content="Stale only" Style="{StaticResource BtnMini}"/>
                  <Button x:Name="btnDrvUnsigned" Content="Unsigned only" Style="{StaticResource BtnMini}"/>
                  <TextBlock x:Name="lblDrvRows" VerticalAlignment="Center" Margin="8,0,0,0" Foreground="{DynamicResource DxMuted}"/>
                </StackPanel>
                <DataGrid Grid.Row="1" x:Name="gridDrivers">
                  <DataGrid.Columns>
                    <DataGridTextColumn Header="Device" Binding="{Binding Device}" Width="250"/>
                    <DataGridTextColumn Header="Class" Binding="{Binding Class}" Width="100"/>
                    <DataGridTextColumn Header="Provider" Binding="{Binding Provider}" Width="150"/>
                    <DataGridTextColumn Header="Version" Binding="{Binding Version}" Width="120"/>
                    <DataGridTextColumn Header="Date" Binding="{Binding DriverDate}" Width="140"/>
                    <DataGridTextColumn Header="Age yr" Binding="{Binding AgeYears}" Width="62"/>
                    <DataGridTextColumn Header="Signed" Binding="{Binding Signed}" Width="62"/>
                    <DataGridTextColumn Header="Flag" Binding="{Binding Flag}" Width="*"/>
                  </DataGrid.Columns>
                </DataGrid>
              </Grid>
            </TabItem>
            <TabItem Header="Boot history">
              <Grid Margin="4">
                <Grid.RowDefinitions><RowDefinition Height="*"/><RowDefinition Height="Auto"/><RowDefinition Height="*"/></Grid.RowDefinitions>
                <DockPanel Grid.Row="0">
                  <TextBlock DockPanel.Dock="Top" Text="BOOT DURATION  (Diagnostics-Performance 100)" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridBootPerf">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                      <DataGridTextColumn Header="Total s" Binding="{Binding BootSec}" Width="76"/>
                      <DataGridTextColumn Header="Main path s" Binding="{Binding MainPathSec}" Width="94"/>
                      <DataGridTextColumn Header="Post boot s" Binding="{Binding PostBootSec}" Width="94"/>
                      <DataGridTextColumn Header="Degradation s" Binding="{Binding DegradationSec}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
                <GridSplitter Grid.Row="1" Style="{StaticResource HSplit}"/>
                <DockPanel Grid.Row="2">
                  <TextBlock DockPanel.Dock="Top" Text="BOOT AND SHUTDOWN EVENTS" Style="{StaticResource CardTitle}"/>
                  <DataGrid x:Name="gridBootEvents" RowStyle="{StaticResource RowWarnAll}">
                    <DataGrid.Columns>
                      <DataGridTextColumn Header="Time" Binding="{Binding Time}" Width="150"/>
                      <DataGridTextColumn Header="ID" Binding="{Binding Id}" Width="56"/>
                      <DataGridTextColumn Header="What happened" Binding="{Binding Kind}" Width="250"/>
                      <DataGridTextColumn Header="Detail" Binding="{Binding Detail}" Width="*"/>
                    </DataGrid.Columns>
                  </DataGrid>
                </DockPanel>
              </Grid>
            </TabItem>
</TabControl>
        </Grid>
      </TabItem>

      <!-- ACTIONS AND REPORT -->
      <TabItem Style="{StaticResource SideNavItem}">
        <TabItem.Header>
          <StackPanel Orientation="Horizontal">
            <Path Style="{StaticResource DxIcon}" Fill="{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}" Margin="0,0,10,0" Data="M14,2H6C4.9,2,4,2.9,4,4v16c0,1.1,0.9,2,2,2h12c1.1,0,2-0.9,2-2V8L14,2z M13,9V3.5L18.5,9H13z M8,13h8v2H8V13z M8,17h8v2H8V17z"/>
            <TextBlock Text="Actions and Report" VerticalAlignment="Center"/>
          </StackPanel>
        </TabItem.Header>
        <Grid Margin="10">
          <Grid.ColumnDefinitions>
            <ColumnDefinition Width="Auto" MinWidth="280"/>
            <ColumnDefinition Width="Auto"/>
            <ColumnDefinition Width="*" MinWidth="250"/>
          </Grid.ColumnDefinitions>
          <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto" Width="330">
            <StackPanel Margin="0,0,8,0">
              <TextBlock Text="Guided remediation" FontSize="15" FontWeight="SemiBold" Margin="0,0,0,4" Foreground="{DynamicResource DxInk}"/>
              <TextBlock Text="Actions run locally and stream output to the console. Items marked (!) change system state and ask for confirmation." TextWrapping="Wrap" Foreground="{DynamicResource DxMuted}" Margin="0,0,0,12" FontSize="11.5"/>
              <TextBlock Text="POLICY" Style="{StaticResource CardTitle}" Margin="0,6,0,4"/>
              <Button x:Name="actGpupdate" Content="Force Group Policy refresh" HorizontalContentAlignment="Left"/>
              <Button x:Name="actGpHtml" Content="Generate RSoP HTML report" HorizontalContentAlignment="Left" Style="{StaticResource BtnGhost}"/>
              <TextBlock Text="NETWORK" Style="{StaticResource CardTitle}" Margin="0,10,0,4"/>
              <Button x:Name="actDns" Content="Flush DNS resolver cache" HorizontalContentAlignment="Left"/>
              <Button x:Name="actRegDns" Content="Re-register DNS records" HorizontalContentAlignment="Left" Style="{StaticResource BtnGhost}"/>
              <Button x:Name="actFwLog" Content="Enable firewall drop logging" HorizontalContentAlignment="Left" Style="{StaticResource BtnGhost}"/>
              <Button x:Name="actRenew" Content="(!) Release and renew DHCP lease" HorizontalContentAlignment="Left" Style="{StaticResource BtnWarn}"/>
              <Button x:Name="actWinsock" Content="(!) Reset Winsock (reboot required)" HorizontalContentAlignment="Left" Style="{StaticResource BtnDanger}"/>
              <Button x:Name="actIpReset" Content="(!) Reset TCP/IP and Winsock stack" HorizontalContentAlignment="Left" Style="{StaticResource BtnDanger}"/>
              <Button x:Name="actFwReset" Content="(!) Reset firewall to defaults" HorizontalContentAlignment="Left" Style="{StaticResource BtnDanger}"/>
              <TextBlock Text="INTUNE AND CERTIFICATES" Style="{StaticResource CardTitle}" Margin="0,10,0,4"/>
              <Button x:Name="actSync" Content="Trigger MDM sync now" HorizontalContentAlignment="Left"/>
              <Button x:Name="actCertPulse" Content="Trigger certificate auto-enrolment" HorizontalContentAlignment="Left" Style="{StaticResource BtnGhost}"/>
              <Button x:Name="actIme" Content="(!) Restart Intune Management Extension" HorizontalContentAlignment="Left" Style="{StaticResource BtnWarn}"/>
              <Button x:Name="actImeCache" Content="(!) Clear IME content cache" HorizontalContentAlignment="Left" Style="{StaticResource BtnWarn}"/>
              <Button x:Name="actMdmDiag" Content="Collect MDM diagnostic bundle" HorizontalContentAlignment="Left" Style="{StaticResource BtnGhost}"/>
              <TextBlock Text="SERVICING AND REPAIR" Style="{StaticResource CardTitle}" Margin="0,10,0,4"/>
              <Button x:Name="actSfc" Content="(!) Run SFC /scannow" HorizontalContentAlignment="Left" Style="{StaticResource BtnWarn}"/>
              <Button x:Name="actDism" Content="(!) Run DISM RestoreHealth" HorizontalContentAlignment="Left" Style="{StaticResource BtnWarn}"/>
              <Button x:Name="actWu" Content="(!) Reset Windows Update cache" HorizontalContentAlignment="Left" Style="{StaticResource BtnDanger}"/>
              <Button x:Name="actSpooler" Content="(!) Restart print spooler" HorizontalContentAlignment="Left" Style="{StaticResource BtnWarn}"/>
              <TextBlock Text="REPORTING" Style="{StaticResource CardTitle}" Margin="0,10,0,4"/>
              <Button x:Name="actHtml" Content="Export full HTML report" HorizontalContentAlignment="Left" Style="{StaticResource BtnOk}"/>
              <Button x:Name="actJson" Content="Export raw findings as JSON" HorizontalContentAlignment="Left" Style="{StaticResource BtnOk}"/>
              <Button x:Name="actCsv" Content="Export event list as CSV" HorizontalContentAlignment="Left" Style="{StaticResource BtnOk}"/>
              <Button x:Name="actCertCsv" Content="Export certificate list as CSV" HorizontalContentAlignment="Left" Style="{StaticResource BtnOk}"/>
              <Button x:Name="actFwCsv" Content="Export firewall rules as CSV" HorizontalContentAlignment="Left" Style="{StaticResource BtnOk}"/>
            </StackPanel>
          </ScrollViewer>
          <GridSplitter Grid.Column="1" Style="{StaticResource VSplit}"/>
          <DockPanel Grid.Column="2">
            <TextBlock DockPanel.Dock="Top" Text="ACTION CONSOLE" Style="{StaticResource CardTitle}"/>
            <Border BorderBrush="{DynamicResource DxConsoleEdge}" BorderThickness="1" Background="{DynamicResource DxConsoleBg}" CornerRadius="8">
              <ScrollViewer VerticalScrollBarVisibility="Auto">
                <TextBox x:Name="txtConsole" IsReadOnly="True" TextWrapping="Wrap" BorderThickness="0" Background="{DynamicResource DxConsoleBg}" Foreground="{DynamicResource DxConsoleFg}" Padding="12" FontFamily="Consolas" FontSize="11.5"/>
              </ScrollViewer>
            </Border>
          </DockPanel>
        </Grid>
      </TabItem>
</TabControl>

    <!-- CONSOLE LAUNCHER -->
    <Border Grid.Row="3" Background="{DynamicResource DxCardBg}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="0,1,0,1" Padding="12,7">
      <DockPanel>
        <TextBlock DockPanel.Dock="Left" Text="CONSOLES" VerticalAlignment="Center" Margin="0,0,10,0" FontSize="10" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}"/>
        <ScrollViewer HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Disabled">
          <StackPanel x:Name="mscPanel" Orientation="Horizontal"/>
        </ScrollViewer>
      </DockPanel>
    </Border>

    <!-- STATUS BAR -->
    <Border Grid.Row="4" Background="{DynamicResource DxStatusBg}" Padding="14,7">
      <Grid>
        <TextBlock x:Name="lblStatus" Text="Ready." Foreground="{DynamicResource DxStatusFg}" VerticalAlignment="Center" TextTrimming="CharacterEllipsis"/>
        <ProgressBar x:Name="pbBusy" Width="220" Height="6" HorizontalAlignment="Right" IsIndeterminate="True" Visibility="Collapsed" Foreground="{DynamicResource DxAccentHi}" Background="{DynamicResource DxTrack}"/>
      </Grid>
    </Border>
  </Grid>
</Window>
'@

# =============================================================================
#  Build the window
# =============================================================================
[xml]$xamlXml = $xamlText
$reader = New-Object System.Xml.XmlNodeReader $xamlXml
$window = [Windows.Markup.XamlReader]::Load($reader)

$UI = @{}
foreach ($node in $xamlXml.SelectNodes("//*[@*[local-name()='Name']]")) {
    $n = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
    if ([string]::IsNullOrEmpty($n)) { $n = $node.GetAttribute('Name') }
    if ($n) { $c = $window.FindName($n); if ($c) { $UI[$n] = $c } }
}

# =============================================================================
#  Crash safety net
# =============================================================================
$script:CrashDir = Join-Path $env:ProgramData 'EndpointDiagX'
$script:CrashLog = Join-Path $script:CrashDir 'crash.log'
if (-not (Test-Path $script:CrashDir)) { New-Item -Path $script:CrashDir -ItemType Directory -Force | Out-Null }
$script:CrashLogWrites = 0

function Write-DxCrash {
    param([string]$Context, $ErrorObject)
    $script:CrashLogWrites++
    if ($script:CrashLogWrites -gt 200) { return 'Crash log cap reached.' }
    try {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine(('=' * 78))
        [void]$sb.AppendLine("TIME     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine("CONTEXT  : $Context")
        [void]$sb.AppendLine("HOST     : $env:COMPUTERNAME / $env:USERNAME  elevated=$script:IsElevated")
        $ex = $ErrorObject
        if ($ErrorObject -is [System.Management.Automation.ErrorRecord]) {
            $ex = $ErrorObject.Exception
            [void]$sb.AppendLine("POSITION : $($ErrorObject.InvocationInfo.PositionMessage)")
        }
        $depth = 0
        while ($ex -and $depth -lt 5) {
            [void]$sb.AppendLine("TYPE     : $($ex.GetType().FullName)")
            [void]$sb.AppendLine("MESSAGE  : $($ex.Message)")
            if ($ex.StackTrace) { [void]$sb.AppendLine("STACK    :`r`n$($ex.StackTrace)") }
            $ex = $ex.InnerException; $depth++
            if ($ex) { [void]$sb.AppendLine('--- inner exception ---') }
        }
        Add-Content -Path $script:CrashLog -Value $sb.ToString() -Encoding UTF8
        return $sb.ToString()
    }
    catch { return "Could not write crash log: $($_.Exception.Message)" }
}

$script:InCrashHandler = $false
$script:CrashCounts = @{}
$script:CrashTotal = 0

$window.Dispatcher.add_UnhandledException({
    param($eventSender, $e)
    $e.Handled = $true
    # NEVER show a modal dialog here: MessageBox pumps the message loop, which
    # runs the next layout pass, which throws again -> infinite dialog cascade.
    if ($script:InCrashHandler) { return }
    $script:InCrashHandler = $true
    try {
        $ex = $e.Exception
        $key = "$($ex.GetType().Name): $($ex.Message)"
        $script:CrashTotal++
        if (-not $script:CrashCounts.ContainsKey($key)) {
            $script:CrashCounts[$key] = 0
            Write-DxCrash -Context 'Dispatcher (UI thread)' -ErrorObject $ex | Out-Null
        }
        $script:CrashCounts[$key]++
        if ($script:CrashCounts[$key] -le 3) {
            try {
                $UI.txtConsole.AppendText("[$(Get-Date -f 'HH:mm:ss')] UI ERROR ($($script:CrashCounts[$key])x): $key`r`n")
                $UI.txtConsole.ScrollToEnd()
            } catch { }
        }
        try { $UI.lblStatus.Text = "Recovered from $script:CrashTotal UI error(s). Latest: $key" } catch { }
    }
    catch { }
    finally { $script:InCrashHandler = $false }
})

[AppDomain]::CurrentDomain.add_UnhandledException({
    param($eventSender, $e)
    Write-DxCrash -Context 'AppDomain (fatal)' -ErrorObject $e.ExceptionObject | Out-Null
})

function Set-DxItems {
    param($Grid, $Items, [string]$Label = 'grid', [int]$Cap = 0)
    try {
        # CRITICAL: @($null) yields a ONE-element array containing $null. A
        # virtualizing ItemsControl keys per-item storage by the item itself, so a
        # null row throws ArgumentNullException ("key") on every layout pass.
        $data = @()
        if ($null -ne $Items) { $data = @($Items) | Where-Object { $null -ne $_ } }
        $data = @($data)
        if ($Cap -gt 0 -and $data.Count -gt $Cap) { $data = @($data | Select-Object -First $Cap) }
        $Grid.ItemsSource = $data
        return $data.Count
    }
    catch {
        Write-DxCrash -Context "Set-DxItems -> $Label" -ErrorObject $_ | Out-Null
        try { $Grid.ItemsSource = @() } catch { }
        return 0
    }
}

function Get-DxJobResult {
    <#
      Background scriptblocks should emit one result object, but stray pipeline
      output shifts index 0. Select by expected property instead of blindly
      taking [0] - that mis-selection renders a tab silently empty.
    #>
    param($Raw, [string[]]$Expect)
    $all = @($Raw) | Where-Object { $null -ne $_ }
    if ($all.Count -eq 0) { return $null }
    if ($Expect -and $Expect.Count -gt 0) {
        foreach ($o in $all) {
            $ok = $true
            foreach ($p in $Expect) { if (-not $o.PSObject.Properties[$p]) { $ok = $false; break } }
            if ($ok) { return $o }
        }
        $types = ($all | ForEach-Object { $_.GetType().Name }) -join ', '
        Write-DxCrash -Context "Get-DxJobResult: no object had [$($Expect -join ',')]; received: $types" -ErrorObject $null | Out-Null
        Write-DxConsole "Background result did not contain [$($Expect -join ', ')]. Received $($all.Count) object(s): $types"
    }
    return $all[0]
}

$UI.lblHost.Text = "$env:COMPUTERNAME  \  $env:USERNAME"
if ($script:IsElevated) { $UI.lblElev.Text = 'Elevated' }
else {
    $UI.lblElev.Text = 'NOT elevated - limited data'
    try { $UI.badgeElev.Background = (New-Object Windows.Media.BrushConverter).ConvertFromString('#66DC2626') } catch { }
}

# =============================================================================
#  THEME ENGINE  (dark / light)
# =============================================================================
#  One vocabulary, three consumers:
#
#    XAML          {DynamicResource DxMuted}
#    runtime ctrl  Set-DxRes $lbl 'Foreground' 'DxMuted'
#    canvas/chart  (Get-DxColor 'DxMuted')
#
#  Every key in $script:DxPalette is pushed into $window.Resources on each
#  theme change, so the first two update live. The third does not - canvases
#  are drawn imperatively, so anything using Get-DxColor must be redrawn by
#  Redraw-DxAllCharts.
#
#  RULE: a key referenced from XAML must exist in BOTH halves of the palette
#  AND be declared as a SolidColorBrush in Window.Resources. A missing
#  declaration does not throw - the control silently keeps an unset brush.
#
#  The header, console and status bar are dark in both themes by design.
#  DxSpotBg is the exception that matters: it is an INVERTED surface, so in
#  Dark it moves LIGHTER than DxCardBg. Keeping it darker (as v4 did, pinned
#  to #FF0F172A) made every spotlight card read as a hole in the page.
# =============================================================================
$script:DxThemeName  = 'Light'
$script:DxThemeFile  = Join-Path $script:CrashDir 'theme.txt'
$script:DxNavFile    = Join-Path $script:CrashDir 'nav.txt'
$script:DxNavCollapsed = $false

$script:DxPalette = @{
    Light = @{
            DxBtnGhostBorder='#FF9585D8';
            DxBtnChipBg='#FF63509E';
            DxBtnGhostBg='#FF6E5AC0';
        # --- surfaces ---
        DxWindowBg='#FFEDF1F7'; DxCardBg='#FFFFFFFF'; DxCardBorder='#FFDCE3ED'
        DxFieldBg='#FFFFFFFF';  DxTabStripBg='#FFF7F9FC'; DxSubtle='#FFF6F8FC'
        DxTrack='#FFE7ECF3';    DxSparkBg='#FFF6F8FC'
        DxNavBg='#FFFFFFFF';    DxNavEdge='#FFDCE3ED'
        # --- ink ---
        DxInk='#FF10182A';      DxInkSoft='#FF334155';  DxMuted='#FF5C6979'
        DxFaint='#FF8B98A9';    DxHeaderFg='#FF44526A'; DxIconFg='#FF5B6878'
        # --- accent ---
        DxAccent='#FF4F46E5';   DxAccentHi='#FF6366F1'; DxAccentPress='#FF4338CA'
        DxOnAccent='#FFFFFFFF'; DxRowHover='#FFE7ECFB'
        DxAccentSoftBg='#FFEEF2FF'; DxAccentSoftEdge='#FFC7D2FE'; DxAccentSoftFg='#FF3730A3'
        DxDisabled='#FFC7D0DC'
        # --- action buttons / semantic solids ---
        DxGhost='#FF475569';    DxOk='#FF059669';   DxWarn='#FFD97706'
        DxWarnAlt='#FFF59E0B';  DxDanger='#FFDC2626'; DxChip='#FF334155'
        DxLossBar='#FFFCA5A5';  DxBadgeOk='#3310B981'; DxBadgeErr='#66DC2626'
        # --- spotlight (inverted surface) ---
        DxSpotBg='#FF131C2E';   DxSpotEdge='#FF131C2E'
        DxSpotFg='#FFF2F5FA';   DxSpotMuted='#FF93A2B8'
        # --- console / status / header ---
        DxConsoleBg='#FF0C1320'; DxConsoleFg='#FF7CE7A8'; DxConsoleEdge='#FF0C1320'
        DxStatusBg='#FF131C2E';  DxStatusFg='#FFC6D0DF'
        DxHeadGrad1='#FF111A2C'; DxHeadGrad2='#FF1C2740'; DxHeadGrad3='#FF2E2C86'
        DxHeadFgSoft='#FFA9B2FA'; DxHeadChipBg='#22FFFFFF'
        # --- charts ---
        DxChartInk='#FF334155';  DxChartAxis='#FFDCE3ED'; DxChartTrack='#FFEDF1F7'
        # --- severity ramp ---
        DxSevCritBg='#FFFEE2E2'; DxSevCritFg='#FF991B1B'; DxSevCritEdge='#FFFECACA'
        DxSevErrBg='#FFFEF2F2';  DxSevErrFg='#FFB91C1C'
        DxSevWarnBg='#FFFFFBEB'; DxSevWarnFg='#FF92400E'; DxSevWarnEdge='#FFFDE68A'; DxSevWarnBg2='#FFFEF3C7'
        DxSevInfoBg='#FFF0F9FF'; DxSevInfoFg='#FF1D4ED8'; DxSevInfoEdge='#FFBFDBFE'
        DxSevInfoBg2='#FFDBEAFE'; DxSevInfoEdge2='#FFBAE6FD'
        DxSevOkBg='#FFF0FDF4';   DxSevOkFg='#FF166534';   DxSevOkEdge='#FFBBF7D0'; DxSevOkBg2='#FFDCFCE7'
        DxSevOrangeBg='#FFFFEDD5'; DxSevOrangeFg='#FF9A3412'; DxSevOrangeEdge='#FFFED7AA'
    }
    Dark = @{
            DxBtnGhostBorder='#FFA090E0';
            DxBtnChipBg='#FF6E5ABE';
            DxBtnGhostBg='#FF7E68C8';
        # --- surfaces: card sits clearly above canvas, border above card ---
        DxWindowBg='#FF080D17'; DxCardBg='#FF121A2A'; DxCardBorder='#FF263248'
        DxFieldBg='#FF0D1524';  DxTabStripBg='#FF0B111E'; DxSubtle='#FF0D1524'
        DxTrack='#FF1A2740';    DxSparkBg='#FF0D1524'
        DxNavBg='#FF141D2E';    DxNavEdge='#FF2A3854'
        # --- ink ---
        DxInk='#FFE7ECF5';      DxInkSoft='#FFC3CEDD';  DxMuted='#FF8E9DB3'
        DxFaint='#FF6E7D93';    DxHeaderFg='#FF9FAEC4'; DxIconFg='#FF9DACC2'
        # --- accent: lightens in Dark, so text ON the accent must darken ---
        DxAccent='#FF818CF8';   DxAccentHi='#FF9BA3FA'; DxAccentPress='#FF6E78EC'
        DxOnAccent='#FF0A0F1A'; DxRowHover='#FF1D2A45'
        DxAccentSoftBg='#FF1A2340'; DxAccentSoftEdge='#FF313C6B'; DxAccentSoftFg='#FFC3C8FC'
        DxDisabled='#FF2C3853'
        # --- action buttons / semantic solids ---
        DxGhost='#FF3A4A63';    DxOk='#FF10B981';   DxWarn='#FFE0932A'
        DxWarnAlt='#FFF0A93A';  DxDanger='#FFE85555'; DxChip='#FF2B3A52'
        DxLossBar='#FFE06B6B';  DxBadgeOk='#3310B981'; DxBadgeErr='#66DC2626'
        # --- spotlight: LIGHTER than DxCardBg, see the note above ---
        DxSpotBg='#FF1E2A44';   DxSpotEdge='#FF33405E'
        DxSpotFg='#FFF0F4FA';   DxSpotMuted='#FFA3B2C8'
        # --- console / status / header ---
        DxConsoleBg='#FF060B13'; DxConsoleFg='#FF86EFAC'; DxConsoleEdge='#FF223049'
        DxStatusBg='#FF0C1424';  DxStatusFg='#FFB9C5D6'
        DxHeadGrad1='#FF0B1220'; DxHeadGrad2='#FF16203A'; DxHeadGrad3='#FF2A2F73'
        DxHeadFgSoft='#FFA8B0F7'; DxHeadChipBg='#1AFFFFFF'
        # --- charts ---
        DxChartInk='#FFC3CEDD';  DxChartAxis='#FF263248'; DxChartTrack='#FF1A2740'
        # --- severity ramp ---
        DxSevCritBg='#FF3A1519'; DxSevCritFg='#FFFCA5A5'; DxSevCritEdge='#FF572026'
        DxSevErrBg='#FF32161A';  DxSevErrFg='#FFF87171'
        DxSevWarnBg='#FF33270B'; DxSevWarnFg='#FFFCD34D'; DxSevWarnEdge='#FF4D3B10'; DxSevWarnBg2='#FF3B2D0C'
        DxSevInfoBg='#FF102540'; DxSevInfoFg='#FF93C5FD'; DxSevInfoEdge='#FF1B3A63'
        DxSevInfoBg2='#FF13294A'; DxSevInfoEdge2='#FF1B3A63'
        DxSevOkBg='#FF0D2B1B';   DxSevOkFg='#FF86EFAC';   DxSevOkEdge='#FF15422A'; DxSevOkBg2='#FF0F3220'
        DxSevOrangeBg='#FF3A2410'; DxSevOrangeFg='#FFFDBA74'; DxSevOrangeEdge='#FF56371A'
    }
}

function Get-DxColor {
    <#
      Hex for a token in the ACTIVE theme. For imperative drawing only
      (canvases, chart text, status colours picked by state). Anything that
      is a DependencyProperty on a live control should use Set-DxRes instead
      so it re-themes without a redraw.
    #>
    param([Parameter(Mandatory)][string]$Name)
    $pal = $script:DxPalette[$script:DxThemeName]
    if (-not $pal) { $pal = $script:DxPalette['Light'] }
    if ($pal.ContainsKey($Name)) { return $pal[$Name] }
    # An unknown token is a typo, not a styling choice - make it loud rather
    # than silently grey, so it is caught in the first run instead of a review.
    Write-DxCrash -Context "Get-DxColor: unknown token '$Name'" -ErrorObject $null | Out-Null
    return '#FFFF00FF'
}

$script:DxDpCache = @{}
function Set-DxRes {
    <#
      The code equivalent of {DynamicResource} for controls built at runtime.

      New-DxBrush hands back a frozen brush, so a control assigned that way is
      pinned to whatever theme was active when it was created - which is why
      the ping/lookup/trace/port cards and their sparklines stayed light after
      switching to Dark. SetResourceReference installs a live link instead.

      The DP is found by reflection because the correct one depends on the
      control: TextBlock.ForegroundProperty and Control.ForegroundProperty are
      different DependencyProperties, and setting the wrong one does nothing
      at all rather than failing.
    #>
    param($Control, [Parameter(Mandatory)][string]$Property, [Parameter(Mandatory)][string]$Key)
    if (-not $Control) { return }
    try {
        $t = $Control.GetType()
        $ck = "$($t.FullName)|$Property"
        $dp = $null
        if ($script:DxDpCache.ContainsKey($ck)) {
            $dp = $script:DxDpCache[$ck]
        } else {
            $f = $t.GetField("${Property}Property", [Reflection.BindingFlags]'Public,Static,FlattenHierarchy')
            if ($f) { $dp = $f.GetValue($null) }
            $script:DxDpCache[$ck] = $dp
        }
        if ($dp) { $Control.SetResourceReference($dp, $Key) }
    } catch { }
}

function Set-DxHeaderBrush {
    <#
      GradientStop.Color takes a Color, not a Brush, so the header gradient
      cannot be expressed with the theme brushes in XAML. Paint it here.
    #>
    try {
        if (-not $UI.brdHeader) { return }
        $g = New-Object Windows.Media.LinearGradientBrush
        $g.StartPoint = New-Object Windows.Point(0,0)
        $g.EndPoint   = New-Object Windows.Point(1,1)
        $cc = New-Object Windows.Media.ColorConverter
        foreach ($stop in @(@('DxHeadGrad1',0.0), @('DxHeadGrad2',0.55), @('DxHeadGrad3',1.0))) {
            $col = $cc.ConvertFromString((Get-DxColor $stop[0]))
            $g.GradientStops.Add((New-Object Windows.Media.GradientStop($col, $stop[1]))) | Out-Null
        }
        $g.Freeze()
        $UI.brdHeader.Background = $g
    } catch { Write-DxCrash -Context 'Set-DxHeaderBrush' -ErrorObject $_ | Out-Null }
}

function Update-DxCardAccents {
    <#
      Card status strips and status labels are coloured by STATE, not by the
      theme, so they are assigned imperatively and cannot use Set-DxRes.
      An idle card would therefore keep its old-theme colour until the next
      tick. Repaint the idle ones and redraw every sparkline.
    #>
    try {
        foreach ($c in @($script:PingCards)) {
            if ($c.UI.Spark) { Show-DxSparkline -Canvas $c.UI.Spark -Values $c.Samples }
            if (-not $c.Running -and $c.Stats.Sent -eq 0) {
                try { $c.UI.Accent.Background = New-DxBrush (Get-DxColor 'DxFaint') } catch { }
            }
        }
        foreach ($set in @($script:LookupCards, $script:TraceCards, $script:PortCards)) {
            foreach ($c in @($set)) {
                if (-not $c) { continue }
                try {
                    if (-not $c.Running) { $c.UI.Accent.Background = New-DxBrush (Get-DxColor 'DxFaint') }
                } catch { }
            }
        }
    } catch { }
}

function Set-DxTheme {
    param([ValidateSet('Light','Dark')][string]$Name = 'Light', [switch]$NoSave)
    try {
        $pal = $script:DxPalette[$Name]
        if (-not $pal) { return }
        $conv = New-Object Windows.Media.BrushConverter
        foreach ($k in $pal.Keys) {
            $b = $null
            try { $b = $conv.ConvertFromString($pal[$k]) } catch { }
            if ($b) { try { $b.Freeze() } catch { }; $window.Resources[$k] = $b }
        }
        $script:DxThemeName = $Name

        # Chart colours come from the palette now rather than a second,
        # separately-maintained set of literals that drifted from it.
        $script:DxChartInk    = $pal['DxChartInk']
        $script:DxChartCardBg = $pal['DxCardBg']
        $script:DxChartTrack  = $pal['DxChartTrack']
        $script:DxChartAxis   = $pal['DxChartAxis']

        $script:BrushCache = @{}          # colours changed - drop cached brushes

        Set-DxHeaderBrush

        if ($UI.btnTheme) {
            if ($Name -eq 'Dark') { $UI.btnTheme.Content = 'Light mode' }
            else { $UI.btnTheme.Content = 'Dark mode' }
        }

        # Not-elevated badge is set imperatively at startup, so re-apply it.
        try {
            if (-not $script:IsElevated -and $UI.badgeElev) {
                $UI.badgeElev.Background = New-DxBrush (Get-DxColor 'DxBadgeErr')
            }
        } catch { }

        try { Redraw-DxAllCharts } catch { }
        try { Update-DxCardAccents } catch { }

        if (-not $NoSave) {
            try { Set-Content -Path $script:DxThemeFile -Value $Name -Encoding UTF8 } catch { }
        }
    }
    catch { Write-DxCrash -Context "Set-DxTheme $Name" -ErrorObject $_ | Out-Null }
}

function Initialize-DxTheme {
    $name = 'Light'
    try {
        if (Test-Path $script:DxThemeFile) {
            $v = (Get-Content -Path $script:DxThemeFile -Raw -ErrorAction Stop).Trim()
            if ($v -eq 'Dark' -or $v -eq 'Light') { $name = $v }
        }
    } catch { }
    Set-DxTheme -Name $name -NoSave
}

function Test-DxThemeTokens {
    <#
      Startup self-check. Every SolidColorBrush declared in the XAML must be
      backed by both palettes, and both palettes must agree on their key set.
      A silent mismatch is precisely the failure mode that stranded three
      brushes inside an XML comment for a whole release, so it is worth one
      pass at launch.
    #>
    $issues = New-Object System.Collections.ArrayList
    try {
        $lk = @($script:DxPalette.Light.Keys)
        $dk = @($script:DxPalette.Dark.Keys)
        foreach ($k in $lk) { if ($dk -notcontains $k) { $null = $issues.Add("Dark palette is missing '$k'") } }
        foreach ($k in $dk) { if ($lk -notcontains $k) { $null = $issues.Add("Light palette is missing '$k'") } }
        foreach ($m in ([regex]::Matches($xamlText, '<SolidColorBrush x:Key="([^"]+)"'))) {
            $k = $m.Groups[1].Value
            if ($lk -notcontains $k) { $null = $issues.Add("XAML declares '$k' but no palette provides it") }
        }
    } catch { }
    return @($issues.ToArray())
}

function Set-DxAppIcon {
    <#
      Loads the .ico for the header badge, the window chrome and the taskbar.
      CacheOption=OnLoad reads the file fully into memory so the icon file is
      not left locked on disk - without it the app holds a handle and the file
      cannot be replaced while running.
    #>
    param([string]$FileName = 'Designer.ico')
    try {
        $p = Join-Path $script:AppRoot $FileName
        if (-not (Test-Path $p)) {
            if ($UI.imgLogo) { $UI.imgLogo.Visibility = 'Collapsed' }
            if ($UI.lblLogoFallback) { $UI.lblLogoFallback.Visibility = 'Visible' }
            Write-DxConsole "Icon '$FileName' not found in $script:AppRoot - using the built-in glyph."
            return
        }
        $bi = New-Object Windows.Media.Imaging.BitmapImage
        $bi.BeginInit()
        $bi.UriSource    = New-Object Uri($p, [UriKind]::Absolute)
        $bi.CacheOption  = [Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bi.CreateOptions= [Windows.Media.Imaging.BitmapCreateOptions]::IgnoreImageCache
        $bi.EndInit()
        try { $bi.Freeze() } catch { }

        if ($UI.imgLogo) {
            $UI.imgLogo.Source = $bi
            $UI.imgLogo.Visibility = 'Visible'
        }
        if ($UI.lblLogoFallback) { $UI.lblLogoFallback.Visibility = 'Collapsed' }
        try { $window.Icon = $bi } catch { }
        Write-DxConsole "Loaded application icon: $FileName"
    }
    catch {
        if ($UI.imgLogo) { $UI.imgLogo.Visibility = 'Collapsed' }
        if ($UI.lblLogoFallback) { $UI.lblLogoFallback.Visibility = 'Visible' }
        Write-DxCrash -Context 'Set-DxAppIcon' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not load '$FileName': $($_.Exception.Message)"
    }
}

# =============================================================================
#  UI plumbing
# =============================================================================
function Set-DxStatus {
    param([string]$Text, [switch]$Busy, [switch]$Done)
    try {
        $UI.lblStatus.Text = $Text
        if ($Busy) { $UI.pbBusy.Visibility = 'Visible' }
        if ($Done) { $UI.pbBusy.Visibility = 'Collapsed' }
        $window.Dispatcher.Invoke([Action]{}, [Windows.Threading.DispatcherPriority]::Render)
    } catch { }
}

function Write-DxConsole {
    param([string]$Text)
    try {
        $UI.txtConsole.AppendText("[$(Get-Date -Format 'HH:mm:ss')] $Text`r`n")
        $UI.txtConsole.ScrollToEnd()
    } catch { }
}

function Start-DxUiJob {
    param(
        [Parameter(Mandatory)][string]$ScriptText,
        [Parameter(Mandatory)][scriptblock]$OnComplete,
        [hashtable]$Arguments = @{},
        [string]$StatusText = 'Working...'
    )
    Set-DxStatus -Text $StatusText -Busy
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('DxEnginePath', $script:EnginePath)
    foreach ($k in $Arguments.Keys) { $rs.SessionStateProxy.SetVariable($k, $Arguments[$k]) }
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $null = $ps.AddScript(". `$DxEnginePath`r`n" + $ScriptText)
    $handle = $ps.BeginInvoke()

    $timer = New-Object Windows.Threading.DispatcherTimer
    $timer.Interval = [TimeSpan]::FromMilliseconds(250)
    $state = [pscustomobject]@{ PS=$ps; RS=$rs; Handle=$handle; Timer=$timer; Callback=$OnComplete }
    $null = $script:Jobs.Add($state)

    $timer.Add_Tick({
        $job = $script:Jobs | Where-Object { $_.Timer -eq $this } | Select-Object -First 1
        if (-not $job) { $this.Stop(); return }
        if (-not $job.Handle.IsCompleted) { return }
        $this.Stop()
        $result = $null; $errText = ''
        try { $result = $job.PS.EndInvoke($job.Handle) } catch { $errText = $_.Exception.Message }
        if ($job.PS.Streams.Error.Count -gt 0) {
            $errText += ($job.PS.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
        }
        $job.PS.Dispose(); $job.RS.Close(); $job.RS.Dispose()
        $script:Jobs.Remove($job)
        Set-DxStatus -Text 'Ready.' -Done
        if ($errText) { Write-DxConsole "Background task reported: $errText" }
        & $job.Callback @($result)
    })
    $timer.Start()
}

function Get-DxSelectedHours {
    $item = $UI.cboHours.SelectedItem
    if ($item -and $item.Tag) { return [int]$item.Tag }
    return 24
}
function Get-DxSelectedLevels {
    $lv = New-Object System.Collections.ArrayList
    if ($UI.chkCritical.IsChecked) { $null = $lv.Add(1) }
    if ($UI.chkError.IsChecked)    { $null = $lv.Add(2) }
    if ($UI.chkWarning.IsChecked)  { $null = $lv.Add(3) }
    if ($UI.chkInfo.IsChecked)     { $null = $lv.Add(4) }
    if ($lv.Count -eq 0) { $null = $lv.Add(2) }
    return @($lv.ToArray())
}
$script:ExtraLogs = @()
function Get-DxSelectedLogs {
    $logs = New-Object System.Collections.ArrayList
    $null = $logs.Add('System'); $null = $logs.Add('Application')
    foreach ($x in $script:ExtraLogs) { if ($x) { $null = $logs.Add($x) } }
    return @($logs.ToArray() | Select-Object -Unique)
}

# =============================================================================
#  Native charts
# =============================================================================
$script:BrushCache = @{}
function New-DxBrush {
    param([string]$Hex)
    if (-not $Hex) { $Hex = (Get-DxColor 'DxFaint') }
    if ($script:BrushCache.ContainsKey($Hex)) { return $script:BrushCache[$Hex] }
    $b = $null
    try { $b = (New-Object Windows.Media.BrushConverter).ConvertFromString($Hex) } catch { }
    if (-not $b) { $b = [Windows.Media.Brushes]::Gray }
    try { $b.Freeze() } catch { }
    $script:BrushCache[$Hex] = $b
    return $b
}

function Get-DxCanvasBox {
    param($Canvas, [double]$DefaultW = 380, [double]$DefaultH = 160)
    $w = $Canvas.ActualWidth
    if (-not $w -or [double]::IsNaN($w) -or $w -lt 20) { $w = $Canvas.Width }
    if (-not $w -or [double]::IsNaN($w) -or $w -lt 20) { $w = $DefaultW }
    $h = $Canvas.ActualHeight
    if (-not $h -or [double]::IsNaN($h) -or $h -lt 20) { $h = $Canvas.Height }
    if (-not $h -or [double]::IsNaN($h) -or $h -lt 20) { $h = $DefaultH }
    return ,@([double]$w, [double]$h)
}

function New-DxText {
    param([string]$Text, [double]$X, [double]$Y, [double]$Size = 11, [string]$Color = $script:DxChartInk, [string]$Weight = 'Normal')
    $t = New-Object Windows.Controls.TextBlock
    $t.Text = $Text; $t.FontSize = $Size; $t.Foreground = New-DxBrush $Color
    if ($Weight -eq 'Bold') { $t.FontWeight = 'Bold' } elseif ($Weight -eq 'SemiBold') { $t.FontWeight = 'SemiBold' }
    [Windows.Controls.Canvas]::SetLeft($t, $X); [Windows.Controls.Canvas]::SetTop($t, $Y)
    return $t
}

function Get-DxArcPoint {
    param([double]$Cx, [double]$Cy, [double]$R, [double]$Deg)
    $rad = $Deg * [math]::PI / 180.0
    New-Object Windows.Point(($Cx + $R * [math]::Cos($rad)), ($Cy + $R * [math]::Sin($rad)))
}

function Show-DxDonut {
    param($Canvas, $Data, [double]$Thickness = 27, [string]$CenterLabel = 'total')
    try {
        $Canvas.Children.Clear()
        $box = Get-DxCanvasBox -Canvas $Canvas -DefaultW 150 -DefaultH 150
        $w = $box[0]; $h = $box[1]; $cx = $w/2; $cy = $h/2
        $r = ([math]::Min($w,$h)/2) - 3
        if ($r -lt 10) { return }
        $d = @()
        if ($null -ne $Data) { $d = @($Data) | Where-Object { $null -ne $_ -and [double]$_.Value -gt 0 } }
        $total = 0.0
        foreach ($x in $d) { $total += [double]$x.Value }
        if ($total -le 0) {
            $Canvas.Children.Add((New-DxText -Text 'No data' -X ($cx-22) -Y ($cy-8) -Size 12 -Color (Get-DxColor 'DxFaint'))) | Out-Null
            return
        }
        if (@($d).Count -eq 1) {
            $e = New-Object Windows.Shapes.Ellipse
            $e.Width = $r*2; $e.Height = $r*2; $e.Fill = New-DxBrush $d[0].Color
            [Windows.Controls.Canvas]::SetLeft($e, $cx-$r); [Windows.Controls.Canvas]::SetTop($e, $cy-$r)
            $Canvas.Children.Add($e) | Out-Null
        } else {
            $angle = -90.0
            foreach ($slice in $d) {
                $sweep = ([double]$slice.Value / $total) * 360.0
                $p1 = Get-DxArcPoint -Cx $cx -Cy $cy -R $r -Deg $angle
                $p2 = Get-DxArcPoint -Cx $cx -Cy $cy -R $r -Deg ($angle + $sweep)
                $fig = New-Object Windows.Media.PathFigure
                $fig.StartPoint = New-Object Windows.Point($cx, $cy)
                $fig.Segments.Add((New-Object Windows.Media.LineSegment($p1, $false)))
                $arc = New-Object Windows.Media.ArcSegment
                $arc.Point = $p2; $arc.Size = New-Object Windows.Size($r, $r)
                $arc.IsLargeArc = ($sweep -gt 180.0)
                $arc.SweepDirection = [Windows.Media.SweepDirection]::Clockwise
                $fig.Segments.Add($arc); $fig.IsClosed = $true
                $geo = New-Object Windows.Media.PathGeometry
                $geo.Figures.Add($fig)
                $path = New-Object Windows.Shapes.Path
                $path.Data = $geo; $path.Fill = New-DxBrush $slice.Color
                $path.ToolTip = "$($slice.Label): $($slice.Value)"
                $Canvas.Children.Add($path) | Out-Null
                $angle += $sweep
            }
        }
        $hole = New-Object Windows.Shapes.Ellipse
        $hr = $r - $Thickness
        if ($hr -lt 8) { $hr = 8 }
        $hole.Width = $hr*2; $hole.Height = $hr*2; $hole.Fill = New-DxBrush $script:DxChartCardBg
        [Windows.Controls.Canvas]::SetLeft($hole, $cx-$hr); [Windows.Controls.Canvas]::SetTop($hole, $cy-$hr)
        $Canvas.Children.Add($hole) | Out-Null
        $Canvas.Children.Add((New-DxText -Text "$([int]$total)" -X ($cx-20) -Y ($cy-18) -Size 19 -Color $script:DxChartInk -Weight 'Bold')) | Out-Null
        $Canvas.Children.Add((New-DxText -Text $CenterLabel -X ($cx-16) -Y ($cy+5) -Size 9.5 -Color (Get-DxColor 'DxFaint'))) | Out-Null
    }
    catch { Write-DxCrash -Context 'Show-DxDonut' -ErrorObject $_ | Out-Null }
}

function Set-DxLegend {
    param($Panel, $Data)
    try {
        $Panel.Children.Clear()
        $d = @()
        if ($null -ne $Data) { $d = @($Data) | Where-Object { $null -ne $_ } }
        $total = 0.0
        foreach ($x in $d) { $total += [double]$x.Value }
        foreach ($item in $d) {
            $row = New-Object Windows.Controls.StackPanel
            $row.Orientation = 'Horizontal'; $row.Margin = '0,0,0,6'
            $dot = New-Object Windows.Controls.Border
            $dot.Width = 10; $dot.Height = 10; $dot.CornerRadius = 3
            $dot.Background = New-DxBrush $item.Color; $dot.VerticalAlignment = 'Center'; $dot.Margin = '0,0,7,0'
            $row.Children.Add($dot) | Out-Null
            $pct = 0
            if ($total -gt 0) { $pct = [math]::Round(([double]$item.Value/$total)*100,1) }
            $t = New-Object Windows.Controls.TextBlock
            $t.Text = "$($item.Label)"; $t.FontSize = 11; $t.Width = 100
            $t.TextTrimming = 'CharacterEllipsis'; $t.Foreground = New-DxBrush (Get-DxColor 'DxInkSoft'); $t.VerticalAlignment = 'Center'
            $row.Children.Add($t) | Out-Null
            $v = New-Object Windows.Controls.TextBlock
            $v.Text = "$($item.Value)  ($pct%)"; $v.FontSize = 11; $v.FontWeight = 'SemiBold'
            $v.Foreground = New-DxBrush (Get-DxColor 'DxInk'); $v.VerticalAlignment = 'Center'
            $row.Children.Add($v) | Out-Null
            $Panel.Children.Add($row) | Out-Null
        }
    }
    catch { Write-DxCrash -Context 'Set-DxLegend' -ErrorObject $_ | Out-Null }
}

function Show-DxHBars {
    param($Canvas, $Data, [double]$LabelW = 160)
    try {
        $Canvas.Children.Clear()
        $box = Get-DxCanvasBox -Canvas $Canvas -DefaultW 400 -DefaultH 160
        $w = $box[0]; $h = $box[1]
        $d = @()
        if ($null -ne $Data) { $d = @($Data) | Where-Object { $null -ne $_ } }
        if ($d.Count -eq 0) {
            $Canvas.Children.Add((New-DxText -Text 'No data' -X 6 -Y ($h/2-8) -Size 12 -Color (Get-DxColor 'DxFaint'))) | Out-Null
            return
        }
        $max = 0.0
        foreach ($x in $d) { if ([double]$x.Value -gt $max) { $max = [double]$x.Value } }
        if ($max -le 0) { $max = 1 }
        if ($LabelW -gt ($w * 0.5)) { $LabelW = $w * 0.5 }
        $rowH = [math]::Min(25.0, $h / $d.Count)
        $barH = [math]::Max(7.0, $rowH - 9)
        $barMax = $w - $LabelW - 48
        if ($barMax -lt 25) { $barMax = 25 }
        $y = 0.0
        foreach ($item in $d) {
            $lbl = New-DxText -Text $item.Label -X 0 -Y ($y + ($rowH-14)/2) -Size 10.5 -Color (Get-DxColor 'DxHeaderFg')
            $Canvas.Children.Add($lbl) | Out-Null
            $track = New-Object Windows.Shapes.Rectangle
            $track.Width = $barMax; $track.Height = $barH; $track.RadiusX = 4; $track.RadiusY = 4
            $track.Fill = New-DxBrush $script:DxChartTrack
            [Windows.Controls.Canvas]::SetLeft($track, $LabelW); [Windows.Controls.Canvas]::SetTop($track, $y + ($rowH-$barH)/2)
            $Canvas.Children.Add($track) | Out-Null
            $bw = ([double]$item.Value / $max) * $barMax
            if ($bw -lt 3) { $bw = 3 }
            $bar = New-Object Windows.Shapes.Rectangle
            $bar.Width = $bw; $bar.Height = $barH; $bar.RadiusX = 4; $bar.RadiusY = 4
            $bar.Fill = New-DxBrush $item.Color; $bar.ToolTip = "$($item.Label): $($item.Value)"
            [Windows.Controls.Canvas]::SetLeft($bar, $LabelW); [Windows.Controls.Canvas]::SetTop($bar, $y + ($rowH-$barH)/2)
            $Canvas.Children.Add($bar) | Out-Null
            $Canvas.Children.Add((New-DxText -Text "$($item.Value)" -X ($LabelW+$barMax+7) -Y ($y + ($rowH-14)/2) -Size 10.5 -Color $script:DxChartInk -Weight 'SemiBold')) | Out-Null
            $y += $rowH
        }
    }
    catch { Write-DxCrash -Context 'Show-DxHBars' -ErrorObject $_ | Out-Null }
}

function Show-DxVBars {
    param($Canvas, $Data)
    try {
        $Canvas.Children.Clear()
        $box = Get-DxCanvasBox -Canvas $Canvas -DefaultW 400 -DefaultH 160
        $w = $box[0]; $h = $box[1]
        $d = @()
        if ($null -ne $Data) { $d = @($Data) | Where-Object { $null -ne $_ } }
        if ($d.Count -eq 0) {
            $Canvas.Children.Add((New-DxText -Text 'No data' -X 6 -Y ($h/2-8) -Size 12 -Color (Get-DxColor 'DxFaint'))) | Out-Null
            return
        }
        $max = 0.0
        foreach ($x in $d) { if ([double]$x.Value -gt $max) { $max = [double]$x.Value } }
        if ($max -le 0) { $max = 1 }
        $axisY = $h - 18; $plotH = $axisY - 14
        if ($plotH -lt 10) { $plotH = 10 }
        $slot = $w / $d.Count
        $barW = [math]::Max(4.0, $slot * 0.62)
        $axis = New-Object Windows.Shapes.Rectangle
        $axis.Width = $w; $axis.Height = 1; $axis.Fill = New-DxBrush $script:DxChartAxis
        [Windows.Controls.Canvas]::SetLeft($axis, 0); [Windows.Controls.Canvas]::SetTop($axis, $axisY)
        $Canvas.Children.Add($axis) | Out-Null
        $i = 0
        foreach ($item in $d) {
            $bh = ([double]$item.Value / $max) * $plotH
            if ($bh -lt 2 -and [double]$item.Value -gt 0) { $bh = 2 }
            $x = ($i * $slot) + (($slot - $barW)/2)
            if ([double]$item.Value -gt 0) {
                $bar = New-Object Windows.Shapes.Rectangle
                $bar.Width = $barW; $bar.Height = $bh; $bar.RadiusX = 3; $bar.RadiusY = 3
                $bar.Fill = New-DxBrush $item.Color; $bar.ToolTip = "$($item.Label): $($item.Value)"
                [Windows.Controls.Canvas]::SetLeft($bar, $x); [Windows.Controls.Canvas]::SetTop($bar, $axisY-$bh)
                $Canvas.Children.Add($bar) | Out-Null
                if ($d.Count -le 14) {
                    $Canvas.Children.Add((New-DxText -Text "$($item.Value)" -X $x -Y ($axisY-$bh-14) -Size 9 -Color (Get-DxColor 'DxMuted'))) | Out-Null
                }
            }
            if ($i % 2 -eq 0 -or $d.Count -le 8) {
                $Canvas.Children.Add((New-DxText -Text $item.Label -X ($x-5) -Y ($axisY+3) -Size 8.5 -Color (Get-DxColor 'DxFaint'))) | Out-Null
            }
            $i++
        }
    }
    catch { Write-DxCrash -Context 'Show-DxVBars' -ErrorObject $_ | Out-Null }
}

function Show-DxSparkline {
    param($Canvas, [object[]]$Values)
    try {
        $Canvas.Children.Clear()
        $box = Get-DxCanvasBox -Canvas $Canvas -DefaultW 300 -DefaultH 54
        $w = $box[0]; $h = $box[1]
        $v = @()
        if ($null -ne $Values) { $v = @($Values) | Where-Object { $null -ne $_ } }
        if ($v.Count -eq 0) {
            $Canvas.Children.Add((New-DxText -Text 'waiting for first reply...' -X 4 -Y ($h/2-8) -Size 10 -Color (Get-DxColor 'DxFaint'))) | Out-Null
            return
        }
        $good = @($v | Where-Object { $_ -ge 0 })
        $max = 1.0
        if ($good.Count -gt 0) { $max = [double](($good | Measure-Object -Maximum).Maximum) }
        if ($max -le 0) { $max = 1 }
        $slot = $w / [math]::Max(1, $v.Count)
        $barW = [math]::Max(1.5, $slot * 0.78)
        for ($i = 0; $i -lt $v.Count; $i++) {
            $val = [double]$v[$i]
            $x = $i * $slot
            if ($val -lt 0) {
                $bar = New-Object Windows.Shapes.Rectangle
                $bar.Width = $barW; $bar.Height = $h; $bar.Fill = New-DxBrush (Get-DxColor 'DxLossBar')
                $bar.ToolTip = 'Request timed out'
                [Windows.Controls.Canvas]::SetLeft($bar, $x); [Windows.Controls.Canvas]::SetTop($bar, 0)
                $Canvas.Children.Add($bar) | Out-Null
            } else {
                $bh = ($val / $max) * ($h - 4)
                if ($bh -lt 2) { $bh = 2 }
                $c = (Get-DxColor 'DxOk')
                if ($val -gt 200) { $c = (Get-DxColor 'DxDanger') } elseif ($val -gt 80) { $c = (Get-DxColor 'DxWarnAlt') }
                $bar = New-Object Windows.Shapes.Rectangle
                $bar.Width = $barW; $bar.Height = $bh; $bar.RadiusX = 1.5; $bar.RadiusY = 1.5
                $bar.Fill = New-DxBrush $c; $bar.ToolTip = "$([int]$val) ms"
                [Windows.Controls.Canvas]::SetLeft($bar, $x); [Windows.Controls.Canvas]::SetTop($bar, $h - $bh)
                $Canvas.Children.Add($bar) | Out-Null
            }
        }
    }
    catch { Write-DxCrash -Context 'Show-DxSparkline' -ErrorObject $_ | Out-Null }
}

# =============================================================================
#  Management console launcher
# =============================================================================
$script:MscList = @(
    [pscustomobject]@{ Label='Event Viewer';     File='eventvwr.msc';        Args='' },
    [pscustomobject]@{ Label='Reliability';      File='perfmon.exe';         Args='/rel' },
    [pscustomobject]@{ Label='Services';         File='services.msc';        Args='' },
    [pscustomobject]@{ Label='Device Manager';   File='devmgmt.msc';         Args='' },
    [pscustomobject]@{ Label='Computer Mgmt';    File='compmgmt.msc';        Args='' },
    [pscustomobject]@{ Label='Task Scheduler';   File='taskschd.msc';        Args='' },
    [pscustomobject]@{ Label='Local GP Editor';  File='gpedit.msc';          Args='' },
    [pscustomobject]@{ Label='GP Management';    File='gpmc.msc';            Args='' },
    [pscustomobject]@{ Label='RSoP';             File='rsop.msc';            Args='' },
    [pscustomobject]@{ Label='Certs (Computer)'; File='certlm.msc';          Args='' },
    [pscustomobject]@{ Label='Certs (User)';     File='certmgr.msc';         Args='' },
    [pscustomobject]@{ Label='Firewall (Adv)';   File='wf.msc';              Args='' },
    [pscustomobject]@{ Label='Local Security';   File='secpol.msc';          Args='' },
    [pscustomobject]@{ Label='Users and Groups'; File='lusrmgr.msc';         Args='' },
    [pscustomobject]@{ Label='Disk Management';  File='diskmgmt.msc';        Args='' },
    [pscustomobject]@{ Label='Print Management'; File='printmanagement.msc'; Args='' },
    [pscustomobject]@{ Label='TPM Management';   File='tpm.msc';             Args='' },
    [pscustomobject]@{ Label='Shared Folders';   File='fsmgmt.msc';          Args='' },
    [pscustomobject]@{ Label='Perf Monitor';     File='perfmon.msc';         Args='' },
    [pscustomobject]@{ Label='Network Conns';    File='ncpa.cpl';            Args='' },
    [pscustomobject]@{ Label='System Info';      File='msinfo32.exe';        Args='' },
    [pscustomobject]@{ Label='Resource Monitor'; File='resmon.exe';          Args='' },
    [pscustomobject]@{ Label='DirectX Diag';     File='dxdiag.exe';          Args='' }
)

function Open-DxConsole {
    param([string]$File, [string]$Arguments = '', [string]$Label = '')
    try {
        $full = Join-Path "$env:SystemRoot\System32" $File
        if (-not (Test-Path $full)) {
            $cmd = Get-Command $File -ErrorAction SilentlyContinue
            if ($cmd) { $full = $cmd.Source }
            else {
                Write-DxConsole "'$Label' ($File) is not present on this SKU. Snap-ins such as gpmc.msc require RSAT."
                return
            }
        }
        if ($Arguments) { Start-Process -FilePath $full -ArgumentList $Arguments | Out-Null }
        else { Start-Process -FilePath $full | Out-Null }
        Write-DxConsole "Opened $Label ($File)."
    }
    catch {
        Write-DxConsole "Could not open '$Label': $($_.Exception.Message)"
        Write-DxCrash -Context "Open-DxConsole $File" -ErrorObject $_ | Out-Null
    }
}

function Initialize-DxMscBar {
    try {
        $style = $window.FindResource('BtnChip')
        foreach ($m in $script:MscList) {
            $b = New-Object Windows.Controls.Button
            $b.Content = $m.Label
            if ($style) { $b.Style = $style }
            $b.Tag = $m
            $b.ToolTip = "$($m.File) $($m.Args)".Trim()
            $b.Add_Click({ $t = $this.Tag; Open-DxConsole -File $t.File -Arguments $t.Args -Label $t.Label })
            $UI.mscPanel.Children.Add($b) | Out-Null
        }
    }
    catch { Write-DxCrash -Context 'Initialize-DxMscBar' -ErrorObject $_ | Out-Null }
}

# =============================================================================
#  PING CARDS  -  each card fully independent (own runspace + timer + stats)
# =============================================================================
$script:PingCards = New-Object System.Collections.ArrayList
$script:PingSeq    = 0
$script:SparkMax   = 60

function Get-DxPingInterval {
    $item = $UI.cboPingInterval.SelectedItem
    if ($item -and $item.Tag) { return [int]$item.Tag }
    return 1000
}

function New-DxCardShell {
    <# Shared chrome for every card type: border, accent strip, header row. #>
    param([double]$Width = 370, [string]$TargetText = '', [string]$RunLabel = 'Start', [string]$RunColorKey = 'DxOk')
    $border = New-Object Windows.Controls.Border
    $border.SetResourceReference([Windows.Controls.Border]::BackgroundProperty, 'DxCardBg')
    $border.SetResourceReference([Windows.Controls.Border]::BorderBrushProperty, 'DxCardBorder')
    $border.BorderThickness = New-Object Windows.Thickness(1)
    $border.CornerRadius = New-Object Windows.CornerRadius(10)
    $border.Margin = New-Object Windows.Thickness(5)
    $border.Width = $Width

    $root = New-Object Windows.Controls.StackPanel
    $accent = New-Object Windows.Controls.Border
    $accent.Height = 5
    Set-DxRes $accent 'Background' 'DxMuted'
    $accent.CornerRadius = New-Object Windows.CornerRadius(9,9,0,0)
    $root.Children.Add($accent) | Out-Null

    $body = New-Object Windows.Controls.StackPanel
    $body.Margin = New-Object Windows.Thickness(13,11,13,11)

    $row1 = New-Object Windows.Controls.DockPanel
    $row1.LastChildFill = $true
    $btnRemove = New-Object Windows.Controls.Button
    $btnRemove.Content = 'X'; $btnRemove.Width = 29
    Set-DxRes $btnRemove 'Background' 'DxDanger'; Set-DxRes $btnRemove 'Foreground' 'DxOnAccent'
    $btnRemove.BorderThickness = New-Object Windows.Thickness(0)
    $btnRemove.Padding = New-Object Windows.Thickness(0,4,0,4)
    $btnRemove.Margin = New-Object Windows.Thickness(5,0,0,0)
    $btnRemove.Cursor = 'Hand'; $btnRemove.FontWeight = 'Bold'
    [Windows.Controls.DockPanel]::SetDock($btnRemove, 'Right')
    $row1.Children.Add($btnRemove) | Out-Null

    $btnRun = New-Object Windows.Controls.Button
    $btnRun.Content = $RunLabel; $btnRun.Width = 68
    Set-DxRes $btnRun 'Background' $RunColorKey; Set-DxRes $btnRun 'Foreground' 'DxOnAccent'
    $btnRun.BorderThickness = New-Object Windows.Thickness(0)
    $btnRun.Padding = New-Object Windows.Thickness(0,4,0,4)
    $btnRun.Margin = New-Object Windows.Thickness(5,0,0,0)
    $btnRun.Cursor = 'Hand'; $btnRun.FontWeight = 'SemiBold'
    [Windows.Controls.DockPanel]::SetDock($btnRun, 'Right')
    $row1.Children.Add($btnRun) | Out-Null

    $txtTarget = New-Object Windows.Controls.TextBox
    $txtTarget.Text = $TargetText; $txtTarget.Height = 26
    $txtTarget.VerticalContentAlignment = 'Center'; $txtTarget.FontWeight = 'SemiBold'
    $row1.Children.Add($txtTarget) | Out-Null
    $body.Children.Add($row1) | Out-Null

    $root.Children.Add($body) | Out-Null
    $border.Child = $root

    [pscustomobject]@{
        Border=$border; Body=$body; Accent=$accent
        Target=$txtTarget; Run=$btnRun; Remove=$btnRemove
    }
}

function New-DxCardRunspace {
    <# A persistent runspace with the engine pre-loaded, one per card. #>
    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'STA'; $rs.ThreadOptions = 'ReuseThread'; $rs.Open()
    $rs.SessionStateProxy.SetVariable('DxEnginePath', $script:EnginePath)
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    $null = $ps.AddScript(". `$DxEnginePath")
    $ps.Invoke() | Out-Null
    $ps.Commands.Clear()
    return [pscustomobject]@{ RS=$rs; PS=$ps }
}

function Update-DxPingCardUi {
    param($Card)
    try {
        $s = $Card.Stats
        $lossPct = 0
        if ($s.Sent -gt 0) { $lossPct = [math]::Round((($s.Sent - $s.Received) / $s.Sent) * 100, 1) }
        $Card.UI.Sent.Text = "$($s.Sent)"
        $Card.UI.Recv.Text = "$($s.Received)"
        $Card.UI.Loss.Text = "$lossPct%"
        if ($s.Received -gt 0) {
            $Card.UI.Last.Text = "$($s.Last) ms"
            $Card.UI.Avg.Text  = "$([math]::Round($s.Total / $s.Received, 1)) ms"
            $Card.UI.MinMax.Text = "$($s.Min) / $($s.Max) ms"
        } else {
            $Card.UI.Last.Text = '--'; $Card.UI.Avg.Text = '--'; $Card.UI.MinMax.Text = '--'
        }
        $col = (Get-DxColor 'DxMuted'); $txt = 'idle'
        if ($Card.Running) {
            if ($s.Sent -eq 0) { $col = (Get-DxColor 'DxAccentHi'); $txt = 'starting' }
            elseif ($s.ConsecutiveLoss -ge 3) { $col = (Get-DxColor 'DxDanger'); $txt = 'UNREACHABLE' }
            elseif ($lossPct -ge 10) { $col = (Get-DxColor 'DxDanger'); $txt = "loss $lossPct%" }
            elseif ($lossPct -gt 0) { $col = (Get-DxColor 'DxWarnAlt'); $txt = "loss $lossPct%" }
            elseif ($s.Last -gt 200) { $col = (Get-DxColor 'DxWarnAlt'); $txt = 'high latency' }
            else { $col = (Get-DxColor 'DxOk'); $txt = 'healthy' }
        } elseif ($s.Sent -gt 0) { $col = (Get-DxColor 'DxMuted'); $txt = 'stopped' }
        $Card.UI.Status.Text = $txt
        $Card.UI.Status.Foreground = New-DxBrush $col
        $Card.UI.Accent.Background = New-DxBrush $col
        $Card.UI.LastError.Text = $s.LastStatus
        Show-DxSparkline -Canvas $Card.UI.Spark -Values $Card.Samples
    }
    catch { Write-DxCrash -Context 'Update-DxPingCardUi' -ErrorObject $_ | Out-Null }
}

function Stop-DxPingCard {
    param($Card)
    try {
        $Card.Running = $false
        if ($Card.Timer) { $Card.Timer.Stop() }
        $Card.UI.Run.Content = 'Start'
        try { Set-DxRes $Card.UI.Run 'Background' 'DxOk' } catch { }
        Update-DxPingCardUi -Card $Card
    }
    catch { Write-DxCrash -Context 'Stop-DxPingCard' -ErrorObject $_ | Out-Null }
}

function Start-DxPingCard {
    param($Card)
    try {
        if ($Card.Running) { return }
        $t = $Card.UI.Target.Text
        if ([string]::IsNullOrWhiteSpace($t)) {
            $Card.Stats.LastStatus = 'Enter a target first.'
            Update-DxPingCardUi -Card $Card
            return
        }
        $Card.Target = $t.Trim()
        $Card.Running = $true
        $Card.UI.Run.Content = 'Stop'
        try { Set-DxRes $Card.UI.Run 'Background' 'DxWarn' } catch { }
        $Card.Timer.Start()
        Update-DxPingCardUi -Card $Card
    }
    catch { Write-DxCrash -Context 'Start-DxPingCard' -ErrorObject $_ | Out-Null }
}

function Remove-DxPingCard {
    param($Card)
    try {
        Stop-DxPingCard -Card $Card
        try { if ($Card.PS) { $Card.PS.Dispose() } } catch { }
        try { if ($Card.RS) { $Card.RS.Close(); $Card.RS.Dispose() } } catch { }
        $UI.pingPanel.Children.Remove($Card.Border)
        $script:PingCards.Remove($Card)
    }
    catch { Write-DxCrash -Context 'Remove-DxPingCard' -ErrorObject $_ | Out-Null }
}

function New-DxPingCard {
    param([string]$Target = '', [int]$IntervalMs = 1000, [switch]$AutoStart)
    try {
        $script:PingSeq++
        $sh = New-DxCardShell -Width 370 -TargetText $Target -RunLabel 'Start' -RunColorKey 'DxOk'
        $body = $sh.Body

        $row2 = New-Object Windows.Controls.StackPanel
        $row2.Orientation = 'Horizontal'
        $row2.Margin = New-Object Windows.Thickness(0,7,0,0)
        $lblStatus = New-Object Windows.Controls.TextBlock
        $lblStatus.Text = 'idle'; $lblStatus.FontSize = 11.5; $lblStatus.FontWeight = 'Bold'
        Set-DxRes $lblStatus 'Foreground' 'DxMuted'
        $row2.Children.Add($lblStatus) | Out-Null
        $lblInterval = New-Object Windows.Controls.TextBlock
        $lblInterval.Text = "   every $([math]::Round($IntervalMs/1000.0,1))s"
        $lblInterval.FontSize = 10.5; $lblInterval.Foreground = New-DxBrush (Get-DxColor 'DxFaint')
        $row2.Children.Add($lblInterval) | Out-Null
        $body.Children.Add($row2) | Out-Null

        $stats = New-Object Windows.Controls.Grid
        $stats.Margin = New-Object Windows.Thickness(0,9,0,0)
        1..4 | ForEach-Object { $stats.ColumnDefinitions.Add((New-Object Windows.Controls.ColumnDefinition)) }
        1..2 | ForEach-Object { $stats.RowDefinitions.Add((New-Object Windows.Controls.RowDefinition)) }
        $cells = @{}
        foreach ($spec in @(
            @{K='Sent';   C='SENT';      Col=0; Row=0},
            @{K='Recv';   C='RECEIVED';  Col=1; Row=0},
            @{K='Loss';   C='LOSS';      Col=2; Row=0},
            @{K='Last';   C='LAST';      Col=3; Row=0},
            @{K='Avg';    C='AVERAGE';   Col=0; Row=1},
            @{K='MinMax'; C='MIN / MAX'; Col=1; Row=1}
        )) {
            $sp = New-Object Windows.Controls.StackPanel
            $c = New-Object Windows.Controls.TextBlock
            $c.Text = $spec.C; $c.FontSize = 9; $c.Foreground = New-DxBrush (Get-DxColor 'DxFaint')
            $v = New-Object Windows.Controls.TextBlock
            $v.Text = '--'; $v.FontSize = 13; $v.FontWeight = 'SemiBold'; $v.Foreground = New-DxBrush (Get-DxColor 'DxInk')
            $sp.Children.Add($c) | Out-Null
            $sp.Children.Add($v) | Out-Null
            [Windows.Controls.Grid]::SetColumn($sp, $spec.Col)
            [Windows.Controls.Grid]::SetRow($sp, $spec.Row)
            $stats.Children.Add($sp) | Out-Null
            $cells[$spec.K] = $v
        }
        $body.Children.Add($stats) | Out-Null

        $sparkLabel = New-Object Windows.Controls.TextBlock
        $sparkLabel.Text = 'LATENCY'
        $sparkLabel.FontSize = 9; $sparkLabel.Foreground = New-DxBrush (Get-DxColor 'DxFaint')
        $sparkLabel.Margin = New-Object Windows.Thickness(0,9,0,3)
        $body.Children.Add($sparkLabel) | Out-Null

        $sparkBorder = New-Object Windows.Controls.Border
        Set-DxRes $sparkBorder 'Background' 'DxSparkBg'
        Set-DxRes $sparkBorder 'BorderBrush' 'DxCardBorder'
        $sparkBorder.BorderThickness = New-Object Windows.Thickness(1)
        $sparkBorder.CornerRadius = New-Object Windows.CornerRadius(6)
        $sparkBorder.Height = 56
        $spark = New-Object Windows.Controls.Canvas
        $spark.Height = 54
        $sparkBorder.Child = $spark
        $body.Children.Add($sparkBorder) | Out-Null

        $lblErr = New-Object Windows.Controls.TextBlock
        $lblErr.Text = ''; $lblErr.FontSize = 10; $lblErr.Foreground = New-DxBrush (Get-DxColor 'DxFaint')
        $lblErr.TextTrimming = 'CharacterEllipsis'
        $lblErr.Margin = New-Object Windows.Thickness(0,6,0,0)
        $body.Children.Add($lblErr) | Out-Null

        $rsp = New-DxCardRunspace
        $timer = New-Object Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds($IntervalMs)

        $card = [pscustomobject]@{
            Id=$script:PingSeq; Target=$Target; IntervalMs=$IntervalMs; Running=$false
            Border=$sh.Border; RS=$rsp.RS; PS=$rsp.PS; Handle=$null; Timer=$timer
            Samples=New-Object System.Collections.ArrayList
            Stats=[pscustomobject]@{ Sent=0; Received=0; Last=0; Total=0.0; Min=0; Max=0; ConsecutiveLoss=0; LastStatus='' }
            UI=@{
                Target=$sh.Target; Run=$sh.Run; Remove=$sh.Remove; Accent=$sh.Accent
                Status=$lblStatus; Spark=$spark; LastError=$lblErr
                Sent=$cells['Sent']; Recv=$cells['Recv']; Loss=$cells['Loss']
                Last=$cells['Last']; Avg=$cells['Avg']; MinMax=$cells['MinMax']
            }
        }

        $timer.Add_Tick({
            $c = $script:PingCards | Where-Object { $_.Timer -eq $this } | Select-Object -First 1
            if (-not $c) { $this.Stop(); return }
            try {
                if ($c.Handle -and $c.Handle.IsCompleted) {
                    $r = $null
                    try { $r = $c.PS.EndInvoke($c.Handle) } catch { }
                    $c.Handle = $null
                    $c.PS.Commands.Clear()
                    $res = @($r) | Where-Object { $null -ne $_ } | Select-Object -First 1
                    if ($res) {
                        $c.Stats.Sent++
                        if ($res.Success) {
                            $c.Stats.Received++
                            $ms = [int]$res.RoundtripMs
                            $c.Stats.Last = $ms
                            $c.Stats.Total += $ms
                            if ($c.Stats.Received -eq 1) { $c.Stats.Min = $ms; $c.Stats.Max = $ms }
                            else {
                                if ($ms -lt $c.Stats.Min) { $c.Stats.Min = $ms }
                                if ($ms -gt $c.Stats.Max) { $c.Stats.Max = $ms }
                            }
                            $c.Stats.ConsecutiveLoss = 0
                            $c.Stats.LastStatus = "reply from $($res.Address)  TTL $($res.Ttl)"
                            $null = $c.Samples.Add($ms)
                        } else {
                            $c.Stats.ConsecutiveLoss++
                            $st = $res.Status
                            if ($res.Error) { $st = $res.Error }
                            $c.Stats.LastStatus = "$st"
                            $null = $c.Samples.Add(-1)
                        }
                        while ($c.Samples.Count -gt $script:SparkMax) { $c.Samples.RemoveAt(0) }
                        Update-DxPingCardUi -Card $c
                    }
                }
                if ($c.Running -and -not $c.Handle) {
                    $t = $c.Target
                    if ([string]::IsNullOrWhiteSpace($t)) { return }
                    # value passed as a runspace VARIABLE - never concatenated into
                    # script text, so nothing the user types can alter the command
                    $c.RS.SessionStateProxy.SetVariable('DxTarget', [string]$t)
                    $c.PS.Commands.Clear()
                    $null = $c.PS.AddScript('Invoke-DxPingOnce -Target $DxTarget -TimeoutMs 1500')
                    $c.Handle = $c.PS.BeginInvoke()
                }
            }
            catch { Write-DxCrash -Context 'PingCard tick' -ErrorObject $_ | Out-Null }
        })

        $sh.Run.Add_Click({
            $c = $script:PingCards | Where-Object { $_.UI.Run -eq $this } | Select-Object -First 1
            if (-not $c) { return }
            if ($c.Running) { Stop-DxPingCard -Card $c } else { Start-DxPingCard -Card $c }
        })
        $sh.Remove.Add_Click({
            $c = $script:PingCards | Where-Object { $_.UI.Remove -eq $this } | Select-Object -First 1
            if ($c) { Remove-DxPingCard -Card $c }
        })
        $sh.Target.Add_KeyDown({
            if ($_.Key -ne 'Return') { return }
            $c = $script:PingCards | Where-Object { $_.UI.Target -eq $this } | Select-Object -First 1
            if (-not $c) { return }
            if ($c.Running) { Stop-DxPingCard -Card $c }
            Start-DxPingCard -Card $c
        })
        $spark.Add_SizeChanged({
            $c = $script:PingCards | Where-Object { $_.UI.Spark -eq $this } | Select-Object -First 1
            if ($c) { Show-DxSparkline -Canvas $this -Values $c.Samples }
        })

        $null = $script:PingCards.Add($card)
        $UI.pingPanel.Children.Add($sh.Border) | Out-Null
        Update-DxPingCardUi -Card $card
        if ($AutoStart -and $Target) { Start-DxPingCard -Card $card }
        return $card
    }
    catch {
        Write-DxCrash -Context 'New-DxPingCard' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not create ping card: $($_.Exception.Message)"
        return $null
    }
}

function Get-DxPingPresets {
    $t = New-Object System.Collections.ArrayList
    Invoke-DxSafe {
        Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
            foreach ($g in @($_.IPv4DefaultGateway.NextHop)) { if ($g) { $null = $t.Add($g) } }
            foreach ($d in @($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | Select-Object -ExpandProperty ServerAddresses)) {
                if ($d -and $d -notmatch '^127\.') { $null = $t.Add($d) }
            }
        }
    }
    $null = $t.Add('login.microsoftonline.com')
    $null = $t.Add('8.8.8.8')
    return @($t.ToArray() | Select-Object -Unique | Select-Object -First 6)
}

# =============================================================================
#  LOOKUP CARDS
# =============================================================================
$script:LookupCards = New-Object System.Collections.ArrayList
$script:LookupSeq = 0

function New-DxCardGrid {
    <# Standard result grid used by lookup / trace / port cards. #>
    param([double]$Height = 150, [object[]]$Cols, [string]$RowStyleKey = '')
    $g = New-Object Windows.Controls.DataGrid
    $g.Height = $Height
    $g.Margin = New-Object Windows.Thickness(0,9,0,0)
    $g.AutoGenerateColumns = $false
    $g.IsReadOnly = $true
    $g.HeadersVisibility = 'Column'
    $g.GridLinesVisibility = 'None'
    $g.FontSize = 11
    $g.RowHeight = 21
    Set-DxRes $g 'BorderBrush' 'DxCardBorder'
    if ($RowStyleKey) { try { $g.RowStyle = $window.FindResource($RowStyleKey) } catch { } }
    foreach ($col in $Cols) {
        $c = New-Object Windows.Controls.DataGridTextColumn
        $c.Header = $col.H
        $c.Binding = New-Object Windows.Data.Binding($col.B)
        if ($col.W -gt 0) { $c.Width = $col.W }
        else { $c.Width = New-Object Windows.Controls.DataGridLength(1, 'Star') }
        $g.Columns.Add($c) | Out-Null
    }
    return $g
}

function Remove-DxLookupCard {
    param($Card)
    try {
        try { if ($Card.Timer) { $Card.Timer.Stop() } } catch { }
        try { if ($Card.PS) { $Card.PS.Dispose() } } catch { }
        try { if ($Card.RS) { $Card.RS.Close(); $Card.RS.Dispose() } } catch { }
        $UI.lookupPanel.Children.Remove($Card.Border)
        $script:LookupCards.Remove($Card)
    }
    catch { Write-DxCrash -Context 'Remove-DxLookupCard' -ErrorObject $_ | Out-Null }
}

function Invoke-DxLookupCard {
    param($Card)
    try {
        $name = $Card.UI.Target.Text
        if (-not $name -or $name.Trim().Length -eq 0) {
            $Card.UI.Status.Text = 'Enter a name first'
            Set-DxRes $Card.UI.Status 'Foreground' 'DxWarn'
            return
        }

        # RECOVERY: a stale handle used to wedge the card permanently - every
        # later click hit "if ($Card.Handle) { return }" and did nothing at all.
        if ($Card.Handle) {
            if ($Card.Handle.IsCompleted) {
                try { $null = $Card.PS.EndInvoke($Card.Handle) } catch { }
                $Card.Handle = $null
                $Card.PS.Commands.Clear()
            }
            elseif ($Card.Started -and ((Get-Date) - $Card.Started).TotalSeconds -gt 20) {
                try { $Card.PS.Stop() } catch { }
                $Card.Handle = $null
                $Card.PS.Commands.Clear()
                Write-DxConsole "Lookup '$name': abandoned a query that ran past 20 seconds."
            }
            else { return }   # genuinely still running
        }

        $type = 'A'
        if ($Card.UI.Type.SelectedItem) { $type = [string]$Card.UI.Type.SelectedItem.Content }
        $server = $Card.UI.Server.Text

        $Card.UI.Status.Text = 'resolving...'
        Set-DxRes $Card.UI.Status 'Foreground' 'DxAccentHi'
        Set-DxRes $Card.UI.Accent 'Background' 'DxAccentHi'
        $Card.UI.Foot.Text = ''

        $Card.RS.SessionStateProxy.SetVariable('DxName', [string]$name)
        $Card.RS.SessionStateProxy.SetVariable('DxType', [string]$type)
        $Card.RS.SessionStateProxy.SetVariable('DxServer', [string]$server)
        $Card.PS.Commands.Clear()
        $Card.PS.Streams.ClearStreams()
        if (-not $server -or $server.Trim().Length -eq 0) {
            $null = $Card.PS.AddScript('Invoke-DxLookup -Name $DxName -Type $DxType')
        } else {
            $null = $Card.PS.AddScript('Invoke-DxLookup -Name $DxName -Type $DxType -Server $DxServer')
        }
        $Card.Handle  = $Card.PS.BeginInvoke()
        Add-Member -InputObject $Card -NotePropertyName 'Started' -NotePropertyValue (Get-Date) -Force
        $Card.Timer.Start()
        Write-DxConsole "Lookup started: $name ($type)$(if($server){" via $server"})"
    }
    catch {
        $Card.UI.Status.Text = 'ERROR'
        Set-DxRes $Card.UI.Status 'Foreground' 'DxDanger'
        $Card.UI.Foot.Text = "$($_.Exception.Message)"
        Write-DxCrash -Context 'Invoke-DxLookupCard' -ErrorObject $_ | Out-Null
        Write-DxConsole "Lookup card failed to start: $($_.Exception.Message)"
    }
}

function New-DxLookupCard {
    param([string]$Name = '', [string]$Type = 'A', [string]$Server = '', [switch]$AutoRun)
    try {
        $script:LookupSeq++
        $sh = New-DxCardShell -Width 460 -TargetText $Name -RunLabel 'Resolve' -RunColorKey 'DxAccent'
        $body = $sh.Body

        $row2 = New-Object Windows.Controls.StackPanel
        $row2.Orientation = 'Horizontal'
        $row2.Margin = New-Object Windows.Thickness(0,7,0,0)
        $cboType = New-Object Windows.Controls.ComboBox
        $cboType.Width = 80; $cboType.Height = 24; $cboType.VerticalContentAlignment = 'Center'
        foreach ($t in @('A','AAAA','CNAME','MX','NS','TXT','SRV','PTR','SOA','ALL')) {
            $it = New-Object Windows.Controls.ComboBoxItem
            $it.Content = $t
            if ($t -eq $Type) { $it.IsSelected = $true }
            $cboType.Items.Add($it) | Out-Null
        }
        if (-not $cboType.SelectedItem) { $cboType.SelectedIndex = 0 }
        $row2.Children.Add($cboType) | Out-Null
        $lblSrv = New-Object Windows.Controls.TextBlock
        $lblSrv.Text = ' server '; $lblSrv.VerticalAlignment = 'Center'
        $lblSrv.FontSize = 10.5; $lblSrv.Foreground = New-DxBrush (Get-DxColor 'DxFaint')
        $lblSrv.Margin = New-Object Windows.Thickness(7,0,4,0)
        $row2.Children.Add($lblSrv) | Out-Null
        $txtServer = New-Object Windows.Controls.TextBox
        $txtServer.Text = $Server; $txtServer.Width = 135; $txtServer.Height = 24
        $txtServer.VerticalContentAlignment = 'Center'
        $txtServer.ToolTip = 'Optional - blank uses the adapter DNS servers'
        $row2.Children.Add($txtServer) | Out-Null
        $lblStatus = New-Object Windows.Controls.TextBlock
        $lblStatus.Text = 'idle'; $lblStatus.FontSize = 11; $lblStatus.FontWeight = 'Bold'
        Set-DxRes $lblStatus 'Foreground' 'DxMuted'
        $lblStatus.VerticalAlignment = 'Center'
        $lblStatus.Margin = New-Object Windows.Thickness(9,0,0,0)
        $row2.Children.Add($lblStatus) | Out-Null
        $body.Children.Add($row2) | Out-Null

        $grid = New-DxCardGrid -Height 150 -Cols @(
            @{H='Record'; B='Name'; W=165}, @{H='Type'; B='Type'; W=58},
            @{H='TTL'; B='TTL'; W=52}, @{H='Data'; B='Data'; W=0}
        )
        $body.Children.Add($grid) | Out-Null

        $lblFoot = New-Object Windows.Controls.TextBlock
        $lblFoot.Text = ''; $lblFoot.FontSize = 10
        Set-DxRes $lblFoot 'Foreground' 'DxFaint'
        $lblFoot.TextWrapping = 'Wrap'
        $lblFoot.Margin = New-Object Windows.Thickness(0,6,0,0)
        $body.Children.Add($lblFoot) | Out-Null

        $rsp = New-DxCardRunspace
        $timer = New-Object Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(200)

        $card = [pscustomobject]@{
            Id=$script:LookupSeq; Border=$sh.Border; RS=$rsp.RS; PS=$rsp.PS; Handle=$null; Timer=$timer
            UI=@{
                Target=$sh.Target; Type=$cboType; Server=$txtServer; Run=$sh.Run; Remove=$sh.Remove
                Status=$lblStatus; Accent=$sh.Accent; Grid=$grid; Foot=$lblFoot
            }
        }

        $timer.Add_Tick({
            $c = $script:LookupCards | Where-Object { $_.Timer -eq $this } | Select-Object -First 1
            if (-not $c) { $this.Stop(); return }
            if (-not $c.Handle) { $this.Stop(); return }
            if (-not $c.Handle.IsCompleted) { return }
            $this.Stop()
            $r = $null
            $invokeErr = ''
            try { $r = $c.PS.EndInvoke($c.Handle) } catch { $invokeErr = $_.Exception.Message }
            if ($c.PS.Streams.Error.Count -gt 0) {
                $invokeErr += ' | ' + (($c.PS.Streams.Error | ForEach-Object { "$_" }) -join '; ')
            }
            if ($invokeErr) { Write-DxConsole "Lookup runspace error: $invokeErr" }
            $c.Handle = $null
            $c.PS.Commands.Clear()
            $res = @($r) | Where-Object { $null -ne $_ } | Select-Object -First 1
            try {
                if (-not $res) {
                    $c.UI.Status.Text = 'no result'
                    Set-DxRes $c.UI.Status 'Foreground' 'DxDanger'
                    Set-DxRes $c.UI.Accent 'Background' 'DxDanger'
                    return
                }
                Set-DxItems -Grid $c.UI.Grid -Items $res.Records -Label 'lookupGrid' | Out-Null
                if ($res.Success) {
                    $c.UI.Status.Text = "$(@($res.Records).Count) record(s)  $($res.Ms) ms"
                    Set-DxRes $c.UI.Status 'Foreground' 'DxOk'
                    Set-DxRes $c.UI.Accent 'Background' 'DxOk'
                    $srv = $res.Server
                    if (-not $srv) { $srv = 'adapter DNS' }
                    $c.UI.Foot.Text = "Resolved via $srv"
                } else {
                    $c.UI.Status.Text = 'FAILED'
                    Set-DxRes $c.UI.Status 'Foreground' 'DxDanger'
                    Set-DxRes $c.UI.Accent 'Background' 'DxDanger'
                    $msg = "$($res.Error)"
                    if ($res.Raw) { $msg = "$msg  |  nslookup: $(($res.Raw -replace '\s+',' ').Trim())" }
                    if ($msg.Length -gt 300) { $msg = $msg.Substring(0,300) + ' ...' }
                    $c.UI.Foot.Text = $msg
                }
            }
            catch { Write-DxCrash -Context 'LookupCard tick' -ErrorObject $_ | Out-Null }
        })

        $sh.Run.Add_Click({
            $c = $script:LookupCards | Where-Object { $_.UI.Run -eq $this } | Select-Object -First 1
            if ($c) { Invoke-DxLookupCard -Card $c }
        })
        $sh.Remove.Add_Click({
            $c = $script:LookupCards | Where-Object { $_.UI.Remove -eq $this } | Select-Object -First 1
            if ($c) { Remove-DxLookupCard -Card $c }
        })
        $sh.Target.Add_KeyDown({
            if ($_.Key -ne 'Return') { return }
            $c = $script:LookupCards | Where-Object { $_.UI.Target -eq $this } | Select-Object -First 1
            if ($c) { Invoke-DxLookupCard -Card $c }
        })

        $null = $script:LookupCards.Add($card)
        $UI.lookupPanel.Children.Add($sh.Border) | Out-Null
        if ($AutoRun -and $Name) { Invoke-DxLookupCard -Card $card }
        return $card
    }
    catch {
        Write-DxCrash -Context 'New-DxLookupCard' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not create lookup card: $($_.Exception.Message)"
        return $null
    }
}

# =============================================================================
#  TRACE ROUTE CARDS  -  one hop per tick so the route builds live
# =============================================================================
$script:TraceCards = New-Object System.Collections.ArrayList
$script:TraceSeq   = 0

function Get-DxTraceMaxHops {
    $item = $UI.cboTraceHops.SelectedItem
    if ($item -and $item.Tag) { return [int]$item.Tag }
    return 30
}

function Update-DxTraceCardUi {
    param($Card)
    try {
        Set-DxItems -Grid $Card.UI.Grid -Items $Card.Hops -Label 'traceGrid' | Out-Null
        $n = @($Card.Hops).Count
        if ($Card.Running) {
            $Card.UI.Status.Text = "tracing... hop $($Card.Ttl) of $($Card.MaxHops)"
            Set-DxRes $Card.UI.Status 'Foreground' 'DxAccentHi'
            Set-DxRes $Card.UI.Accent 'Background' 'DxAccentHi'
        }
        elseif ($Card.Completed) {
            if ($Card.Reached) {
                $ms = 0
                $last = @($Card.Hops) | Select-Object -Last 1
                if ($last) { $ms = $last.Ms }
                $Card.UI.Status.Text = "destination reached in $n hop(s), $ms ms"
                Set-DxRes $Card.UI.Status 'Foreground' 'DxOk'
                Set-DxRes $Card.UI.Accent 'Background' 'DxOk'
            } else {
                $Card.UI.Status.Text = "stopped after $n hop(s) - destination not reached"
                Set-DxRes $Card.UI.Status 'Foreground' 'DxDanger'
                Set-DxRes $Card.UI.Accent 'Background' 'DxDanger'
            }
        }
        elseif ($n -gt 0) {
            $Card.UI.Status.Text = "stopped at hop $n"
            Set-DxRes $Card.UI.Status 'Foreground' 'DxMuted'
            Set-DxRes $Card.UI.Accent 'Background' 'DxMuted'
        }
        else {
            $Card.UI.Status.Text = 'idle'
            Set-DxRes $Card.UI.Status 'Foreground' 'DxMuted'
            Set-DxRes $Card.UI.Accent 'Background' 'DxMuted'
        }
        $timeouts = @($Card.Hops | Where-Object { $_.State -eq 'No reply' }).Count
        if ($timeouts -gt 0) {
            $Card.UI.Foot.Text = "$timeouts hop(s) did not reply. Routers commonly suppress ICMP, so gaps mid-route are normal - only a gap that never recovers indicates a real break."
        } else { $Card.UI.Foot.Text = '' }
    }
    catch { Write-DxCrash -Context 'Update-DxTraceCardUi' -ErrorObject $_ | Out-Null }
}

function Stop-DxTraceCard {
    param($Card)
    try {
        $Card.Running = $false
        if ($Card.Timer) { $Card.Timer.Stop() }
        $Card.UI.Run.Content = 'Trace'
        try { Set-DxRes $Card.UI.Run 'Background' 'DxAccent' } catch { }
        Update-DxTraceCardUi -Card $Card
    }
    catch { Write-DxCrash -Context 'Stop-DxTraceCard' -ErrorObject $_ | Out-Null }
}

function Start-DxTraceCard {
    param($Card)
    try {
        if ($Card.Running) { return }
        $t = $Card.UI.Target.Text
        if ([string]::IsNullOrWhiteSpace($t)) {
            $Card.UI.Status.Text = 'Enter a target first'
            Set-DxRes $Card.UI.Status 'Foreground' 'DxWarn'
            return
        }
        $Card.Target = $t.Trim()
        $Card.Hops.Clear()
        $Card.Ttl = 1
        $Card.Running = $true
        $Card.Completed = $false
        $Card.Reached = $false
        $Card.Handle = $null
        $Card.UI.Run.Content = 'Stop'
        try { Set-DxRes $Card.UI.Run 'Background' 'DxWarn' } catch { }
        $Card.Timer.Start()
        Update-DxTraceCardUi -Card $Card
    }
    catch { Write-DxCrash -Context 'Start-DxTraceCard' -ErrorObject $_ | Out-Null }
}

function Remove-DxTraceCard {
    param($Card)
    try {
        Stop-DxTraceCard -Card $Card
        try { if ($Card.PS) { $Card.PS.Dispose() } } catch { }
        try { if ($Card.RS) { $Card.RS.Close(); $Card.RS.Dispose() } } catch { }
        $UI.tracePanel.Children.Remove($Card.Border)
        $script:TraceCards.Remove($Card)
    }
    catch { Write-DxCrash -Context 'Remove-DxTraceCard' -ErrorObject $_ | Out-Null }
}

function New-DxTraceCard {
    param([string]$Target = '', [int]$MaxHops = 30, [bool]$ResolveNames = $true, [switch]$AutoStart)
    try {
        $script:TraceSeq++
        $sh = New-DxCardShell -Width 510 -TargetText $Target -RunLabel 'Trace' -RunColorKey 'DxAccent'
        $body = $sh.Body

        $row2 = New-Object Windows.Controls.StackPanel
        $row2.Orientation = 'Horizontal'
        $row2.Margin = New-Object Windows.Thickness(0,7,0,0)
        $lblStatus = New-Object Windows.Controls.TextBlock
        $lblStatus.Text = 'idle'; $lblStatus.FontSize = 11.5; $lblStatus.FontWeight = 'Bold'
        Set-DxRes $lblStatus 'Foreground' 'DxMuted'
        $row2.Children.Add($lblStatus) | Out-Null
        $lblCfg = New-Object Windows.Controls.TextBlock
        $lblCfg.Text = "   max $MaxHops hops"
        if ($ResolveNames) { $lblCfg.Text += ', names on' }
        $lblCfg.FontSize = 10.5; $lblCfg.Foreground = New-DxBrush (Get-DxColor 'DxFaint')
        $row2.Children.Add($lblCfg) | Out-Null
        $body.Children.Add($row2) | Out-Null

        $grid = New-DxCardGrid -Height 225 -RowStyleKey 'RowHop' -Cols @(
            @{H='Hop'; B='Hop'; W=40}, @{H='ms'; B='Ms'; W=52},
            @{H='Address'; B='Address'; W=120}, @{H='Host name'; B='HostName'; W=0},
            @{H='State'; B='State'; W=85}
        )
        $body.Children.Add($grid) | Out-Null

        $lblFoot = New-Object Windows.Controls.TextBlock
        $lblFoot.Text = ''; $lblFoot.FontSize = 10
        Set-DxRes $lblFoot 'Foreground' 'DxFaint'
        $lblFoot.TextWrapping = 'Wrap'
        $lblFoot.Margin = New-Object Windows.Thickness(0,6,0,0)
        $body.Children.Add($lblFoot) | Out-Null

        $rsp = New-DxCardRunspace
        $timer = New-Object Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(150)

        $card = [pscustomobject]@{
            Id=$script:TraceSeq; Target=$Target; MaxHops=$MaxHops; ResolveNames=$ResolveNames
            Ttl=1; Running=$false; Completed=$false; Reached=$false
            Border=$sh.Border; RS=$rsp.RS; PS=$rsp.PS; Handle=$null; Timer=$timer
            Hops=New-Object System.Collections.ArrayList
            UI=@{
                Target=$sh.Target; Run=$sh.Run; Remove=$sh.Remove; Accent=$sh.Accent
                Status=$lblStatus; Grid=$grid; Foot=$lblFoot
            }
        }

        $timer.Add_Tick({
            $c = $script:TraceCards | Where-Object { $_.Timer -eq $this } | Select-Object -First 1
            if (-not $c) { $this.Stop(); return }
            try {
                if ($c.Handle -and $c.Handle.IsCompleted) {
                    $r = $null
                    try { $r = $c.PS.EndInvoke($c.Handle) } catch { }
                    $c.Handle = $null
                    $c.PS.Commands.Clear()
                    $res = @($r) | Where-Object { $null -ne $_ } | Select-Object -First 1
                    if ($res) {
                        $state = 'Hop'
                        if ($res.IsDestination) { $state = 'Destination' }
                        elseif ($res.Status -eq 'Error') { $state = 'Error' }
                        elseif (-not $res.Success) { $state = 'No reply' }
                        elseif ($res.RoundtripMs -gt 150) { $state = 'Slow' }
                        $addr = $res.Address
                        if (-not $addr) { $addr = '*' }
                        $msTxt = $res.RoundtripMs
                        if ($res.RoundtripMs -lt 0) { $msTxt = '*' }
                        $null = $c.Hops.Add([pscustomobject]@{
                            Hop=$res.Hop; Ms=$msTxt; Address=$addr; HostName=$res.HostName; State=$state
                        })
                        if ($res.IsDestination) { $c.Reached = $true; $c.Completed = $true; Stop-DxTraceCard -Card $c; return }
                        if ($res.Status -eq 'Error') { $c.Completed = $true; Stop-DxTraceCard -Card $c; return }
                        $c.Ttl++
                        if ($c.Ttl -gt $c.MaxHops) { $c.Completed = $true; Stop-DxTraceCard -Card $c; return }
                        Update-DxTraceCardUi -Card $c
                    }
                }
                if ($c.Running -and -not $c.Handle) {
                    if ([string]::IsNullOrWhiteSpace($c.Target)) { return }
                    $c.RS.SessionStateProxy.SetVariable('DxTarget', [string]$c.Target)
                    $c.RS.SessionStateProxy.SetVariable('DxTtl', [int]$c.Ttl)
                    $c.RS.SessionStateProxy.SetVariable('DxNames', [bool]$c.ResolveNames)
                    $c.PS.Commands.Clear()
                    $null = $c.PS.AddScript('Invoke-DxTraceHop -Target $DxTarget -Ttl $DxTtl -TimeoutMs 2000 -ResolveNames:$DxNames')
                    $c.Handle = $c.PS.BeginInvoke()
                }
            }
            catch { Write-DxCrash -Context 'TraceCard tick' -ErrorObject $_ | Out-Null }
        })

        $sh.Run.Add_Click({
            $c = $script:TraceCards | Where-Object { $_.UI.Run -eq $this } | Select-Object -First 1
            if (-not $c) { return }
            if ($c.Running) { Stop-DxTraceCard -Card $c } else { Start-DxTraceCard -Card $c }
        })
        $sh.Remove.Add_Click({
            $c = $script:TraceCards | Where-Object { $_.UI.Remove -eq $this } | Select-Object -First 1
            if ($c) { Remove-DxTraceCard -Card $c }
        })
        $sh.Target.Add_KeyDown({
            if ($_.Key -ne 'Return') { return }
            $c = $script:TraceCards | Where-Object { $_.UI.Target -eq $this } | Select-Object -First 1
            if (-not $c) { return }
            if ($c.Running) { Stop-DxTraceCard -Card $c }
            Start-DxTraceCard -Card $c
        })

        $null = $script:TraceCards.Add($card)
        $UI.tracePanel.Children.Add($sh.Border) | Out-Null
        Update-DxTraceCardUi -Card $card
        if ($AutoStart -and $Target) { Start-DxTraceCard -Card $card }
        return $card
    }
    catch {
        Write-DxCrash -Context 'New-DxTraceCard' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not create trace card: $($_.Exception.Message)"
        return $null
    }
}

# =============================================================================
#  PORT CHECK CARDS
# =============================================================================
$script:PortCards = New-Object System.Collections.ArrayList
$script:PortSeq   = 0

function Update-DxPortCardUi {
    param($Card)
    try {
        Set-DxItems -Grid $Card.UI.Grid -Items $Card.Results -Label 'portGrid' | Out-Null
        $done = @($Card.Results).Count
        $open = @($Card.Results | Where-Object { $_.Open }).Count
        $total = @($Card.Ports).Count
        if ($Card.Running) {
            $Card.UI.Status.Text = "checking $done of $total ..."
            Set-DxRes $Card.UI.Status 'Foreground' 'DxAccentHi'
            Set-DxRes $Card.UI.Accent 'Background' 'DxAccentHi'
        }
        elseif ($done -eq 0) {
            $Card.UI.Status.Text = 'idle'
            Set-DxRes $Card.UI.Status 'Foreground' 'DxMuted'
            Set-DxRes $Card.UI.Accent 'Background' 'DxMuted'
        }
        else {
            $Card.UI.Status.Text = "$open of $done port(s) open"
            if ($open -eq $done) {
                Set-DxRes $Card.UI.Status 'Foreground' 'DxOk'
                Set-DxRes $Card.UI.Accent 'Background' 'DxOk'
            } elseif ($open -eq 0) {
                Set-DxRes $Card.UI.Status 'Foreground' 'DxDanger'
                Set-DxRes $Card.UI.Accent 'Background' 'DxDanger'
            } else {
                Set-DxRes $Card.UI.Status 'Foreground' 'DxWarn'
                Set-DxRes $Card.UI.Accent 'Background' 'DxWarn'
            }
        }
        $closed = @($Card.Results | Where-Object { -not $_.Open })
        if ($closed.Count -gt 0) {
            $first = $closed | Select-Object -First 1
            $Card.UI.Foot.Text = "Closed example - port $($first.Port): $($first.Error)"
        } else { $Card.UI.Foot.Text = '' }
    }
    catch { Write-DxCrash -Context 'Update-DxPortCardUi' -ErrorObject $_ | Out-Null }
}

function Stop-DxPortCard {
    param($Card)
    try {
        $Card.Running = $false
        if ($Card.Timer) { $Card.Timer.Stop() }
        $Card.UI.Run.Content = 'Check'
        try { Set-DxRes $Card.UI.Run 'Background' 'DxAccent' } catch { }
        Update-DxPortCardUi -Card $Card
    }
    catch { Write-DxCrash -Context 'Stop-DxPortCard' -ErrorObject $_ | Out-Null }
}

function Start-DxPortCard {
    param($Card)
    try {
        if ($Card.Running) { return }
        $t = $Card.UI.Target.Text
        if ([string]::IsNullOrWhiteSpace($t)) {
            $Card.UI.Status.Text = 'Enter a target first'
            Set-DxRes $Card.UI.Status 'Foreground' 'DxWarn'
            return
        }
        $ports = Expand-DxPortList -Text $Card.UI.Ports.Text -Max 256
        if (@($ports).Count -eq 0) {
            $Card.UI.Status.Text = 'No valid ports listed'
            Set-DxRes $Card.UI.Status 'Foreground' 'DxWarn'
            return
        }
        $Card.Target = $t.Trim()
        $Card.Ports = @($ports)
        $Card.Index = 0
        $Card.Results.Clear()
        $Card.Running = $true
        $Card.Handle = $null
        $Card.UI.Run.Content = 'Stop'
        try { Set-DxRes $Card.UI.Run 'Background' 'DxWarn' } catch { }
        $Card.Timer.Start()
        Update-DxPortCardUi -Card $Card
    }
    catch { Write-DxCrash -Context 'Start-DxPortCard' -ErrorObject $_ | Out-Null }
}

function Remove-DxPortCard {
    param($Card)
    try {
        Stop-DxPortCard -Card $Card
        try { if ($Card.PS) { $Card.PS.Dispose() } } catch { }
        try { if ($Card.RS) { $Card.RS.Close(); $Card.RS.Dispose() } } catch { }
        $UI.portPanel.Children.Remove($Card.Border)
        $script:PortCards.Remove($Card)
    }
    catch { Write-DxCrash -Context 'Remove-DxPortCard' -ErrorObject $_ | Out-Null }
}

function New-DxPortCard {
    param([string]$Target = '', [string]$Ports = '443,80', [switch]$AutoStart)
    try {
        $script:PortSeq++
        $sh = New-DxCardShell -Width 460 -TargetText $Target -RunLabel 'Check' -RunColorKey 'DxAccent'
        $body = $sh.Body

        $row2 = New-Object Windows.Controls.DockPanel
        $row2.LastChildFill = $true
        $row2.Margin = New-Object Windows.Thickness(0,7,0,0)
        $lblStatus = New-Object Windows.Controls.TextBlock
        $lblStatus.Text = 'idle'; $lblStatus.FontSize = 11.5; $lblStatus.FontWeight = 'Bold'
        Set-DxRes $lblStatus 'Foreground' 'DxMuted'
        $lblStatus.VerticalAlignment = 'Center'
        $lblStatus.Margin = New-Object Windows.Thickness(8,0,0,0)
        [Windows.Controls.DockPanel]::SetDock($lblStatus, 'Right')
        $row2.Children.Add($lblStatus) | Out-Null
        $txtPorts = New-Object Windows.Controls.TextBox
        $txtPorts.Text = $Ports; $txtPorts.Height = 24
        $txtPorts.VerticalContentAlignment = 'Center'
        $txtPorts.ToolTip = 'Comma separated, ranges allowed (for example 443,80,5985-5986)'
        $row2.Children.Add($txtPorts) | Out-Null
        $body.Children.Add($row2) | Out-Null

        $grid = New-DxCardGrid -Height 195 -RowStyleKey 'RowPort' -Cols @(
            @{H='Port'; B='Port'; W=52}, @{H='State'; B='State'; W=62},
            @{H='ms'; B='Ms'; W=52}, @{H='Service'; B='Service'; W=0}
        )
        $body.Children.Add($grid) | Out-Null

        $lblFoot = New-Object Windows.Controls.TextBlock
        $lblFoot.Text = ''; $lblFoot.FontSize = 10
        Set-DxRes $lblFoot 'Foreground' 'DxFaint'
        $lblFoot.TextWrapping = 'Wrap'
        $lblFoot.Margin = New-Object Windows.Thickness(0,6,0,0)
        $body.Children.Add($lblFoot) | Out-Null

        $rsp = New-DxCardRunspace
        $timer = New-Object Windows.Threading.DispatcherTimer
        $timer.Interval = [TimeSpan]::FromMilliseconds(150)

        $card = [pscustomobject]@{
            Id=$script:PortSeq; Target=$Target; Ports=@(); Index=0; Running=$false
            Border=$sh.Border; RS=$rsp.RS; PS=$rsp.PS; Handle=$null; Timer=$timer
            Results=New-Object System.Collections.ArrayList
            UI=@{
                Target=$sh.Target; Ports=$txtPorts; Run=$sh.Run; Remove=$sh.Remove
                Status=$lblStatus; Accent=$sh.Accent; Grid=$grid; Foot=$lblFoot
            }
        }

        $timer.Add_Tick({
            $c = $script:PortCards | Where-Object { $_.Timer -eq $this } | Select-Object -First 1
            if (-not $c) { $this.Stop(); return }
            try {
                if ($c.Handle -and $c.Handle.IsCompleted) {
                    $r = $null
                    try { $r = $c.PS.EndInvoke($c.Handle) } catch { }
                    $c.Handle = $null
                    $c.PS.Commands.Clear()
                    $res = @($r) | Where-Object { $null -ne $_ } | Select-Object -First 1
                    if ($res) { $null = $c.Results.Add($res); $c.Index++; Update-DxPortCardUi -Card $c }
                    if ($c.Index -ge @($c.Ports).Count) { Stop-DxPortCard -Card $c; return }
                }
                if ($c.Running -and -not $c.Handle -and $c.Index -lt @($c.Ports).Count) {
                    $p = [int](@($c.Ports)[$c.Index])
                    $c.RS.SessionStateProxy.SetVariable('DxTarget', [string]$c.Target)
                    $c.RS.SessionStateProxy.SetVariable('DxPort', $p)
                    $c.PS.Commands.Clear()
                    $null = $c.PS.AddScript('Test-DxPortQuick -Target $DxTarget -Port $DxPort -TimeoutMs 2000')
                    $c.Handle = $c.PS.BeginInvoke()
                }
            }
            catch { Write-DxCrash -Context 'PortCard tick' -ErrorObject $_ | Out-Null }
        })

        $sh.Run.Add_Click({
            $c = $script:PortCards | Where-Object { $_.UI.Run -eq $this } | Select-Object -First 1
            if (-not $c) { return }
            if ($c.Running) { Stop-DxPortCard -Card $c } else { Start-DxPortCard -Card $c }
        })
        $sh.Remove.Add_Click({
            $c = $script:PortCards | Where-Object { $_.UI.Remove -eq $this } | Select-Object -First 1
            if ($c) { Remove-DxPortCard -Card $c }
        })
        $sh.Target.Add_KeyDown({
            if ($_.Key -ne 'Return') { return }
            $c = $script:PortCards | Where-Object { $_.UI.Target -eq $this } | Select-Object -First 1
            if ($c) { if ($c.Running) { Stop-DxPortCard -Card $c }; Start-DxPortCard -Card $c }
        })
        $txtPorts.Add_KeyDown({
            if ($_.Key -ne 'Return') { return }
            $c = $script:PortCards | Where-Object { $_.UI.Ports -eq $this } | Select-Object -First 1
            if ($c) { if ($c.Running) { Stop-DxPortCard -Card $c }; Start-DxPortCard -Card $c }
        })

        $null = $script:PortCards.Add($card)
        $UI.portPanel.Children.Add($sh.Border) | Out-Null
        Update-DxPortCardUi -Card $card
        if ($AutoStart -and $Target) { Start-DxPortCard -Card $card }
        return $card
    }
    catch {
        Write-DxCrash -Context 'New-DxPortCard' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not create port card: $($_.Exception.Message)"
        return $null
    }
}

# =============================================================================
#  Tab update functions
# =============================================================================

# =============================================================================
#  DASHBOARD  -  KPI cards and the posture strip
# =============================================================================

function Update-DxDashboardKpis {
    <#
      Each card is a different DIMENSION. Severity counts are deliberately not
      here - the donut legend already prints them, and four cards restating one
      chart was most of the old KPI strip.
    #>
    try {
        $s   = $script:Data.Snapshot
        $adv = $script:Data.Adv

        # ---- tightest volume: the one about to cause a call ----
        if ($s -and @($s.Disks).Count -gt 0) {
            $tight = @(@($s.Disks) | Sort-Object FreePct) | Select-Object -First 1
            if ($tight) {
                $UI.kpiStorage.Text = "$($tight.FreePct)%"
                $UI.lblStorageNote.Text = "$($tight.Drive) free - $($tight.FreeGB) of $($tight.SizeGB) GB"
            }
        }

        # ---- memory ----
        if ($s -and $null -ne $s.MemoryUsedPct) {
            $UI.kpiMemory.Text = "$($s.MemoryUsedPct)%"
            $UI.lblMemoryNote.Text = "$($s.MemoryFreeGB) GB free of $($s.MemoryTotalGB) GB"
        }

        # ---- reboot / boot quality ----
        if ($adv -and $adv.Uptime -and $adv.Uptime.UncleanCount -gt 0) {
            $UI.kpiReboot.Text = "$($adv.Uptime.UncleanCount) unclean shutdown(s)"
        }

        # ---- posture roll-up: n of m checks passing ----
        $checks = @(Get-DxPostureChecks)
        $known  = @($checks | Where-Object { $_.State -ne 'Unknown' })
        $bad    = @($checks | Where-Object { $_.State -eq 'Bad' -or $_.State -eq 'Warn' })
        if (@($known).Count -eq 0) {
            $UI.kpiPosture.Text = '--'
            $UI.lblPostureNote.Text = 'run a full scan'
        } else {
            $UI.kpiPosture.Text = "$(@($known).Count - @($bad).Count)/$(@($known).Count)"
            if (@($bad).Count -eq 0) {
                $UI.lblPostureNote.Text = 'all checked controls pass'
            } else {
                $UI.lblPostureNote.Text = "worst: $(@($bad)[0].Label) - $(@($bad)[0].Value)"
            }
        }
    }
    catch { Write-DxCrash -Context 'Update-DxDashboardKpis' -ErrorObject $_ | Out-Null }
}

function New-DxCheck {
    param([string]$Label, $Value, [string]$State = 'Unknown')
    [pscustomobject]@{ Label=$Label; Value="$Value"; State=$State }
}

function Get-DxPostureChecks {
    <#
      One row per control, each guarded on its own.

      Only fields whose names and meaning are confirmed are turned into a
      pass/fail state. Where a collector is present but the semantics are
      ambiguous, the check is reported as Unknown rather than guessed - a
      confidently wrong green pill is worse than an honest grey one.
    #>
    $out = New-Object System.Collections.ArrayList
    $s   = $script:Data.Snapshot
    $adv = $script:Data.Adv

    if ($s) {
        try {
            $v = "$($s.SecureBoot)"
            $st = 'Unknown'
            if ($v -match '(?i)^(true|enabled)$') { $st = 'Ok' } elseif ($v -match '(?i)^(false|disabled)$') { $st = 'Bad' }
            $null = $out.Add((New-DxCheck 'Secure Boot' $v $st))
        } catch { }
        try {
            $st = 'Unknown'
            if ("$($s.TpmReady)" -match '(?i)^true$') { $st = 'Ok' } elseif ("$($s.TpmReady)" -match '(?i)^false$') { $st = 'Bad' }
            $null = $out.Add((New-DxCheck 'TPM' "ready=$($s.TpmReady)" $st))
        } catch { }
        try {
            $v = "$($s.BitLockerStatus)"
            $st = 'Unknown'
            if ($v -match '(?i)^on$') { $st = 'Ok' } elseif ($v) { $st = 'Bad' }
            $null = $out.Add((New-DxCheck 'BitLocker C:' $v $st))
        } catch { }
        try {
            $st = 'Unknown'
            if ("$($s.DefenderRTP)" -match '(?i)^true$') { $st = 'Ok' } elseif ("$($s.DefenderRTP)" -match '(?i)^false$') { $st = 'Bad' }
            $age = $s.DefenderSigAge
            if ($st -eq 'Ok' -and $null -ne $age -and [int]$age -gt 7) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'Defender' "RTP=$($s.DefenderRTP), sig $age d" $st))
        } catch { }
        try {
            if (@($s.Disks).Count -gt 0) {
                $t = @(@($s.Disks) | Sort-Object FreePct)[0]
                $st = 'Ok'
                if ($t.FreePct -lt 10) { $st = 'Bad' } elseif ($t.FreePct -lt 20) { $st = 'Warn' }
                $null = $out.Add((New-DxCheck 'Disk space' "$($t.Drive) $($t.FreePct)% free" $st))
            }
        } catch { }
        try {
            if ($null -ne $s.MemoryUsedPct) {
                $st = 'Ok'
                if ([int]$s.MemoryUsedPct -ge 90) { $st = 'Bad' } elseif ([int]$s.MemoryUsedPct -ge 80) { $st = 'Warn' }
                $null = $out.Add((New-DxCheck 'Memory' "$($s.MemoryUsedPct)% used" $st))
            }
        } catch { }
    }

    if ($script:Data.SysDiag -and $script:Data.SysDiag.PendingReboot) {
        try {
            $p = [bool]$script:Data.SysDiag.PendingReboot.Pending
            $st = 'Ok'; $txt = 'none'
            if ($p) { $st = 'Warn'; $txt = 'pending' }
            $null = $out.Add((New-DxCheck 'Reboot' $txt $st))
        } catch { }
    }

    if ($adv) {
        try {
            $r = @($adv.Posture.Rows | Where-Object { $_.Setting -eq 'HVCI (memory integrity)' }) | Select-Object -First 1
            if ($r) {
                $st = 'Warn'
                if ("$($r.Value)" -match '(?i)^running$') { $st = 'Ok' }
                elseif ("$($r.Value)" -match '(?i)not configured') { $st = 'Unknown' }
                $null = $out.Add((New-DxCheck 'HVCI' $r.Value $st))
            }
        } catch { }
        try {
            if ($null -ne $adv.Battery.WorstWearPct) {
                $w = [double]$adv.Battery.WorstWearPct
                $st = 'Ok'
                if ($w -ge 40) { $st = 'Bad' } elseif ($w -ge 25) { $st = 'Warn' }
                $null = $out.Add((New-DxCheck 'Battery' "$w% worn" $st))
            }
        } catch { }
        try {
            $worn = @(@($adv.Storage.Disks) | Where-Object { $null -ne $_.WearPct } | Sort-Object WearPct -Descending)
            if (@($worn).Count -gt 0) {
                $w = [double]$worn[0].WearPct
                $st = 'Ok'
                if ($w -ge 80) { $st = 'Bad' } elseif ($w -ge 50) { $st = 'Warn' }
                $null = $out.Add((New-DxCheck 'SSD wear' "$w%" $st))
            }
        } catch { }
        try {
            $u = @($adv.Drivers.Unsigned).Count
            $st = 'Ok'; if ($u -gt 0) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'Drivers' "$u unsigned" $st))
        } catch { }
        try {
            $c = [int]$adv.Uptime.UncleanCount
            $st = 'Ok'; if ($c -ge 3) { $st = 'Bad' } elseif ($c -gt 0) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'Clean boots' "$c unclean" $st))
        } catch { }
    }

    if ($script:Data.CertSummary) {
        try {
            $e = [int]$script:Data.CertSummary.Expired
            $st = 'Ok'; if ($e -gt 0) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'Certificates' "$e expired" $st))
        } catch { }
    }
    if ($script:Data.Dns) {
        try {
            $n = @($script:Data.Dns.Issues).Count
            $st = 'Ok'; if ($n -gt 0) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'DNS' "$n issue(s)" $st))
        } catch { }
    }
    if ($script:Data.Intune) {
        try {
            $n = @($script:Data.Intune.Issues).Count
            $st = 'Ok'; if ($n -gt 0) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'Intune' "$n issue(s)" $st))
        } catch { }
    }
    if ($script:Data.Policy -and $script:Data.Policy.Counts) {
        try {
            $c = $script:Data.Policy.Counts
            $st = 'Ok'; if ([int]$c.Conflicts -gt 0) { $st = 'Warn' }
            $null = $out.Add((New-DxCheck 'Policy' "$($c.Mdm) CSP / $($c.Gpo) GPO" $st))
        } catch { }
    }

    return @($out.ToArray())
}

function New-DxStatusPill {
    param([string]$Label, [string]$Value, [string]$State)
    $bg = 'DxSubtle'; $fg = 'DxMuted'; $edge = 'DxCardBorder'
    switch ($State) {
        'Ok'   { $bg = 'DxSevOkBg';   $fg = 'DxSevOkFg';   $edge = 'DxSevOkEdge' }
        'Warn' { $bg = 'DxSevWarnBg'; $fg = 'DxSevWarnFg'; $edge = 'DxSevWarnEdge' }
        'Bad'  { $bg = 'DxSevCritBg'; $fg = 'DxSevCritFg'; $edge = 'DxSevCritEdge' }
    }
    $b = New-Object Windows.Controls.Border
    $b.CornerRadius = New-Object Windows.CornerRadius(13)
    $b.BorderThickness = New-Object Windows.Thickness(1)
    $b.Padding = New-Object Windows.Thickness(11,5,11,5)
    $b.Margin = New-Object Windows.Thickness(0,3,7,3)
    # Set-DxRes, not New-DxBrush: pills are built once per scan and would
    # otherwise stay pinned to the theme that was active at the time.
    Set-DxRes $b 'Background' $bg
    Set-DxRes $b 'BorderBrush' $edge

    $sp = New-Object Windows.Controls.StackPanel
    $sp.Orientation = 'Horizontal'

    $l = New-Object Windows.Controls.TextBlock
    $l.Text = $Label
    $l.FontSize = 11
    $l.FontWeight = 'SemiBold'
    Set-DxRes $l 'Foreground' $fg

    $v = New-Object Windows.Controls.TextBlock
    $v.Text = "  $Value"
    $v.FontSize = 11
    $v.Opacity = 0.85
    Set-DxRes $v 'Foreground' $fg

    $null = $sp.Children.Add($l)
    $null = $sp.Children.Add($v)
    $b.Child = $sp
    return $b
}

function Update-DxPostureStrip {
    try {
        $panel = $UI.spPosture
        if (-not $panel) { return }
        $panel.Children.Clear()
        $checks = @(Get-DxPostureChecks)
        if (@($checks).Count -eq 0) {
            $t = New-Object Windows.Controls.TextBlock
            $t.Text = 'Run a full scan to populate the posture summary.'
            $t.FontSize = 11.5
            Set-DxRes $t 'Foreground' 'DxMuted'
            $null = $panel.Children.Add($t)
            return
        }
        # worst first - the point of the strip is what needs attention
        $order = @{ 'Bad'=0; 'Warn'=1; 'Unknown'=2; 'Ok'=3 }
        foreach ($c in @($checks | Sort-Object @{ Expression = { $order["$($_.State)"] } }, Label)) {
            $null = $panel.Children.Add((New-DxStatusPill -Label $c.Label -Value $c.Value -State $c.State))
        }
    }
    catch { Write-DxCrash -Context 'Update-DxPostureStrip' -ErrorObject $_ | Out-Null }
}

function Update-DxDashboard {
    $s = $script:Data.Snapshot
    if ($s) {
        $rows = @(
            [pscustomobject]@{ Property='Computer';         Value=$s.ComputerName },
            [pscustomobject]@{ Property='Signed-in user';   Value=$s.UserName },
            [pscustomobject]@{ Property='Manufacturer';     Value="$($s.Manufacturer) $($s.Model)" },
            [pscustomobject]@{ Property='Serial number';    Value=$s.SerialNumber },
            [pscustomobject]@{ Property='Operating system'; Value="$($s.OSName) $($s.DisplayVersion)" },
            [pscustomobject]@{ Property='Build';            Value="$($s.Build)  ($($s.Architecture))" },
            [pscustomobject]@{ Property='Domain';           Value=$s.Domain },
            [pscustomobject]@{ Property='CPU';              Value=$s.CPU },
            [pscustomobject]@{ Property='Memory';           Value="$($s.MemoryTotalGB) GB total / $($s.MemoryFreeGB) GB free ($($s.MemoryUsedPct)% used)" },
            [pscustomobject]@{ Property='Last boot';        Value="$($s.LastBoot)" },
            [pscustomobject]@{ Property='BIOS';             Value="$($s.BiosVersion)  ($($s.BiosDate))" },
            [pscustomobject]@{ Property='TPM';              Value="Present=$($s.TpmPresent)  Ready=$($s.TpmReady)  Ver=$($s.TpmVersion)" },
            [pscustomobject]@{ Property='Secure Boot';      Value="$($s.SecureBoot)" },
            [pscustomobject]@{ Property='BitLocker (C:)';   Value="$($s.BitLockerStatus)  $($s.BitLockerPct)%" },
            [pscustomobject]@{ Property='Defender RTP';     Value="$($s.DefenderRTP)  (signature age $($s.DefenderSigAge) days)" },
            [pscustomobject]@{ Property='PowerShell';       Value=$s.PSVersion }
        )
        foreach ($d in @($s.Disks)) {
            $rows += [pscustomobject]@{ Property="Disk $($d.Drive)"; Value="$($d.FreeGB) GB free of $($d.SizeGB) GB  ($($d.FreePct)%)" }
        }
        Set-DxItems -Grid $UI.gridSystem -Items $rows -Label 'gridSystem' | Out-Null
        $UI.kpiUptime.Text = $s.UptimeText
        $UI.lblSubtitle.Text = "$($s.OSName) $($s.DisplayVersion) - build $($s.Build) - $($s.Manufacturer) $($s.Model)"
    }
    $st = $script:Data.EventStats
    if ($st) {
        $UI.kpiEvents.Text = $st.Total
        $UI.lblEventMix.Text = "$($st.Critical) critical, $($st.Error) error, $($st.Warning) warning"
    }
    $h = $script:Data.Health
    if ($h) {
        $UI.kpiScore.Text = $h.Score; $UI.kpiGrade.Text = $h.Grade
        Set-DxItems -Grid $UI.gridDeduct -Items $h.Deductions -Label 'gridDeduct' | Out-Null
    }
    Set-DxItems -Grid $UI.gridTop -Items $script:Data.EventSummary -Label 'gridTop' -Cap 40 | Out-Null
    Set-DxItems -Grid $UI.gridIssues -Items $script:Data.EventSummary -Label 'gridIssues' | Out-Null
    Update-DxDashboardKpis
    Update-DxPostureStrip
    Update-DxDashboardCharts
}

function Update-DxDashboardCharts {
    try {
        $sev = Get-DxSeverityChartData -Stats $script:Data.EventStats
        Show-DxDonut -Canvas $UI.cvSeverity -Data $sev -CenterLabel 'events'
        Set-DxLegend -Panel $UI.spSeverityLegend -Data $sev
        Show-DxHBars -Canvas $UI.cvProviders -Data (Get-DxTopProviders -Events $script:Data.Events -Top 7)
        Show-DxVBars -Canvas $UI.cvTimeline -Data (Get-DxEventTimeline -Events $script:Data.Events -Buckets 12)
        Show-DxHBars -Canvas $UI.cvDashDisks -Data (Get-DxDiskChartData -Snapshot $script:Data.Snapshot) -LabelW 150
    }
    catch { Write-DxCrash -Context 'Update-DxDashboardCharts' -ErrorObject $_ | Out-Null }
}

function Update-DxEventGrid {
    param([string]$Filter = '')
    $ev = @($script:Data.Events)
    $logSel = $UI.cboLog.Text
    if ($logSel -and $logSel -ne 'All logs') { $ev = @($ev | Where-Object { $_.LogName -eq $logSel }) }
    if ($Filter) {
        $ev = @($ev | Where-Object {
            $_.Message -match [regex]::Escape($Filter) -or $_.Provider -match [regex]::Escape($Filter) -or "$($_.Id)" -eq $Filter })
    }
    $shown = Set-DxItems -Grid $UI.gridEvents -Items $ev -Label 'gridEvents' -Cap 2000
    $UI.lblEventCount.Text = "$shown shown of $(@($script:Data.Events).Count) collected"
}

function Update-DxFirewallTab {
    $f = $script:Data.Firewall
    if (-not $f) { return }
    try {
        $on = @($f.Profiles | Where-Object { $_.Enabled }).Count
        $tot = @($f.Profiles).Count
        $UI.kpiFwOn.Text = "$on/$tot"
        $UI.kpiFwSvc.Text = if ($f.Service) { "$($f.Service.Status)" } else { 'unknown' }
        $UI.kpiFwRules.Text = $f.RuleStats.Enabled
        $UI.kpiFwInAllow.Text = $f.RuleStats.InboundAllow
        $UI.kpiFwBlocked.Text = @($f.BlockedEvents).Count
        Set-DxItems -Grid $UI.gridFwProfiles -Items $f.Profiles -Label 'gridFwProfiles' | Out-Null
        Set-DxItems -Grid $UI.gridFwConn -Items $f.ConnectionProfiles -Label 'gridFwConn' | Out-Null
        Set-DxItems -Grid $UI.gridFwLog -Items $f.LogRows -Label 'gridFwLog' -Cap 250 | Out-Null
        Set-DxItems -Grid $UI.gridFwBlocked -Items $f.BlockedEvents -Label 'gridFwBlocked' -Cap 150 | Out-Null
        $find = @($f.Issues)
        foreach ($e in @($f.SectionErrors)) { $find = @("SECTION ERROR $e") + $find }
        if (@($find).Count -eq 0) { $find = @('No firewall data was returned.') }
        Set-DxItems -Grid $UI.lstFwFindings -Items $find -Label 'lstFwFindings' | Out-Null
        Show-DxHBars -Canvas $UI.cvFwRules -Data $f.RuleChart -LabelW 110
        $UI.lblFwLog.Text = "FIREWALL LOG  ($($f.LogPath))"
        Find-DxFwRules
    }
    catch { Write-DxCrash -Context 'Update-DxFirewallTab' -ErrorObject $_ | Out-Null }
}

function Find-DxFwRules {
    $f = $script:Data.Firewall
    if (-not $f) { return }
    try {
        $r = @($f.Rules)
        $dir = 'All'; $act = 'All'
        if ($UI.cboFwDir.SelectedItem) { $dir = [string]$UI.cboFwDir.SelectedItem.Content }
        if ($UI.cboFwAction.SelectedItem) { $act = [string]$UI.cboFwAction.SelectedItem.Content }
        if ($dir -ne 'All') { $r = @($r | Where-Object { $_.Direction -eq $dir }) }
        if ($act -ne 'All') { $r = @($r | Where-Object { $_.Action -eq $act }) }
        $q = $UI.txtFwFind.Text
        if (-not [string]::IsNullOrWhiteSpace($q)) {
            $rx = [regex]::Escape($q)
            $r = @($r | Where-Object {
                $_.DisplayName -match $rx -or $_.Group -match $rx -or $_.Program -match $rx -or
                $_.LocalPort -match $rx -or $_.Profile -match $rx })
        }
        $shown = Set-DxItems -Grid $UI.gridFwRules -Items $r -Label 'gridFwRules' -Cap 800
        $UI.lblFwRows.Text = "showing $shown of $(@($f.Rules).Count) enabled rule(s)"
    }
    catch { Write-DxCrash -Context 'Find-DxFwRules' -ErrorObject $_ | Out-Null }
}

function Update-DxDnsTab {
    $d = $script:Data.Dns
    if (-not $d) {
        Set-DxItems -Grid $UI.lstDnsFindings -Items @('No DNS data yet. Click "Analyse firewall and DNS" or run a full scan.') -Label 'lstDnsFindings' | Out-Null
        return
    }
    try {
        $nSrv = Set-DxItems -Grid $UI.gridDnsServers -Items $d.Servers -Label 'gridDnsServers'
        Set-DxItems -Grid $UI.gridDnsReach -Items $d.Reachability -Label 'gridDnsReach' | Out-Null
        Set-DxItems -Grid $UI.gridDnsProbes -Items $d.Probes -Label 'gridDnsProbes' | Out-Null
        Set-DxItems -Grid $UI.gridDnsSuffix -Items $d.Clients -Label 'gridDnsSuffix' | Out-Null
        $findings = @($d.Issues)
        if (@($d.Servers).Count -eq 0 -and @($d.Probes | Where-Object { $_.Resolved }).Count -eq 0) {
            $mr = $d.ModuleReport
            if ($mr -and @($mr.Failed).Count -gt 0) {
                $findings = @("MODULE LOAD FAILED: $((@($mr.Failed)) -join ' | ')") + $findings
            }
        }
        if (@($findings).Count -eq 0) { $findings = @('No DNS data was returned.') }
        Set-DxItems -Grid $UI.lstDnsFindings -Items $findings -Label 'lstDnsFindings' | Out-Null
        Show-DxHBars -Canvas $UI.cvDnsProbe -Data $d.ProbeChart -LabelW 190
        Find-DxDnsCache
        Write-DxConsole "DNS source - servers via $($d.SourceServers), cache via $($d.SourceCache), probes via $($d.SourceProbe)  ($nSrv adapter(s))."
    }
    catch { Write-DxCrash -Context 'Update-DxDnsTab' -ErrorObject $_ | Out-Null }
}

function Find-DxDnsCache {
    $d = $script:Data.Dns
    if (-not $d) { return }
    try {
        $c = @($d.Cache)
        $q = $UI.txtDnsCacheFind.Text
        if (-not [string]::IsNullOrWhiteSpace($q)) {
            $rx = [regex]::Escape($q)
            $c = @($c | Where-Object { $_.Entry -match $rx -or $_.Name -match $rx -or $_.Data -match $rx })
        }
        $shown = Set-DxItems -Grid $UI.gridDnsCache -Items $c -Label 'gridDnsCache' -Cap 400
        $src = ''
        if ($d.SourceCache -and $d.SourceCache -ne 'none') { $src = "  -  via $($d.SourceCache)" }
        $UI.lblDnsCacheRows.Text = "showing $shown of $(@($d.Cache).Count) cached record(s)$src"
    }
    catch { Write-DxCrash -Context 'Find-DxDnsCache' -ErrorObject $_ | Out-Null }
}

function Update-DxNetSummary {
    try {
        $bits = New-Object System.Collections.ArrayList
        $f = $script:Data.Firewall
        if ($f) {
            $on = @($f.Profiles | Where-Object { $_.Enabled }).Count
            $null = $bits.Add("firewall $on/$(@($f.Profiles).Count) on")
            $null = $bits.Add("$($f.RuleStats.Enabled) rules")
        }
        $d = $script:Data.Dns
        if ($d) {
            $bad = @($d.Reachability | Where-Object { -not $_.Reachable }).Count
            $null = $bits.Add("$(@($d.Reachability).Count) DNS server(s), $bad unreachable")
        }
        $null = $bits.Add("$($script:PingCards.Count) ping")
        $null = $bits.Add("$($script:LookupCards.Count) lookup")
        $null = $bits.Add("$($script:TraceCards.Count) trace")
        $null = $bits.Add("$($script:PortCards.Count) port card(s)")
        $UI.lblNetSummary.Text = (@($bits.ToArray()) -join '  |  ')
    }
    catch { }
}

function Update-DxCertTab {
    $sum = $script:Data.CertSummary
    try {
        if ($sum) {
            $UI.kpiCertTotal.Text = $sum.Total; $UI.kpiCertDevice.Text = $sum.Device
            $UI.kpiCertUser.Text = $sum.User; $UI.kpiCertExpired.Text = $sum.Expired
            $UI.kpiCertSoon.Text = $sum.Critical; $UI.kpiCertValid.Text = $sum.Valid
            Show-DxDonut -Canvas $UI.cvCertStatus -Data $sum.StatusChart -CenterLabel 'certs'
            Set-DxLegend -Panel $UI.spCertLegend -Data $sum.StatusChart
            Show-DxHBars -Canvas $UI.cvCertPurpose -Data $sum.PurposeChart -LabelW 175
        }
        Set-DxItems -Grid $UI.lstCertFindings -Items $script:Data.CertFindings -Label 'lstCertFindings' | Out-Null
        Show-DxCertGrid
    }
    catch { Write-DxCrash -Context 'Update-DxCertTab' -ErrorObject $_ | Out-Null }
}

function Show-DxCertGrid {
    try {
        $certs = @($script:Data.Certs)
        $scope = 'All'
        if ($UI.cboCertScope.SelectedItem) { $scope = [string]$UI.cboCertScope.SelectedItem.Content }
        if ($scope -ne 'All') { $certs = @($certs | Where-Object { $_.Scope -eq $scope }) }
        $q = $UI.txtCertFind.Text
        if (-not [string]::IsNullOrWhiteSpace($q)) {
            $rx = [regex]::Escape($q)
            $certs = @($certs | Where-Object {
                $_.SubjectCN -match $rx -or $_.IssuerCN -match $rx -or $_.Purpose -match $rx -or
                $_.Thumbprint -match $rx -or $_.Template -match $rx -or $_.Eku -match $rx })
        }
        $shown = Set-DxItems -Grid $UI.gridCerts -Items $certs -Label 'gridCerts' -Cap 1500
        $UI.lblCertSummary.Text = "INVENTORY - showing $shown of $(@($script:Data.Certs).Count) certificate(s), soonest expiry first"
    }
    catch { Write-DxCrash -Context 'Show-DxCertGrid' -ErrorObject $_ | Out-Null }
}

function Get-DxText {
    <# Flattens any value to a display string. Arrays render as
       "System.Object[]" in a DataGrid otherwise. #>
    param($Value, [int]$Max = 0)
    if ($null -eq $Value) { return '' }
    $s = ''
    try {
        if ($Value -is [string]) { $s = $Value }
        elseif ($Value -is [System.Collections.IEnumerable]) { $s = ((@($Value) | ForEach-Object { "$_" }) -join ', ') }
        else { $s = "$Value" }
    } catch { $s = "$Value" }
    if ($Max -gt 0 -and $s.Length -gt $Max) { $s = $s.Substring(0, $Max) + '...' }
    return $s
}

function Get-DxActiveEnrollment {
    <#
      Picks ONE enrolment, defensively. Uses foreach/break rather than
      @(...)[0] or Where-Object because those unroll nested collections and
      hand back an array - which is why the grid showed every enrolment
      joined together. Also flattens one level in case the collector
      returned a nested array.
    #>
    param($Intune)

    $flat = New-Object System.Collections.ArrayList
    try {
        foreach ($e in @($Intune.Enrollments)) {
            if ($null -eq $e) { continue }
            if ($e -is [System.Collections.IEnumerable] -and $e -isnot [string]) {
                foreach ($x in $e) { if ($null -ne $x) { $null = $flat.Add($x) } }
            } else {
                $null = $flat.Add($e)
            }
        }
    } catch { }
    $items = @($flat.ToArray())

    # 1. the live MDM enrolment
    $pick = $null
    foreach ($e in $items) {
        if ("$($e.ProviderID)" -eq 'MS DM Server' -and "$($e.EnrollmentState)" -eq '1') { $pick = $e; break }
    }
    # 2. any enrolment that actually names a provider
    if (-not $pick) { foreach ($e in $items) { if ("$($e.ProviderID)") { $pick = $e; break } } }
    # 3. anything at all
    if (-not $pick -and $items.Count -gt 0) { $pick = $items[0] }

    if (-not $pick) {
        $pick = [pscustomobject]@{ EnrollmentId=''; ProviderID=''; EnrollmentState=''; EnrollmentType=''; UPN=''; DiscoveryUrl='' }
    }
    Add-Member -InputObject $pick -NotePropertyName 'TotalFound' -NotePropertyValue $items.Count -Force
    return $pick
}

function Update-DxIntuneTab {
    $i = $script:Data.Intune
    if (-not $i) { return }
    $act = Get-DxActiveEnrollment -Intune $i
    $rows = @(
        [pscustomobject]@{ Property='Entra (Azure AD) joined'; Value=$i.DsReg.AzureAdJoined },
        [pscustomobject]@{ Property='Domain joined';            Value=$i.DsReg.DomainJoined },
        [pscustomobject]@{ Property='Enterprise joined';        Value=$i.DsReg.EnterpriseJoined },
        [pscustomobject]@{ Property='Entra PRT present';        Value=$i.DsReg.AzureAdPrt },
        [pscustomobject]@{ Property='Device ID';                Value=$i.DsReg.DeviceId },
        [pscustomobject]@{ Property='Tenant';                   Value="$($i.DsReg.TenantName)  $($i.DsReg.TenantId)" },
        [pscustomobject]@{ Property='MDM URL';                  Value=$i.DsReg.MdmUrl },
        [pscustomobject]@{ Property='MDM compliance URL';       Value=$i.DsReg.MdmComplianceUrl },
        [pscustomobject]@{ Property='Enrollment ID';            Value=(Get-DxText $act.EnrollmentId) },
        [pscustomobject]@{ Property='Enrollment provider';      Value=(Get-DxText $act.ProviderID) },
        [pscustomobject]@{ Property='Enrollment state';         Value=(Get-DxText $act.EnrollmentState) },
        [pscustomobject]@{ Property='Enrollment type';          Value=(Get-DxText $act.EnrollmentType) },
        [pscustomobject]@{ Property='Enrolled UPN';             Value=(Get-DxText $act.UPN) },
        [pscustomobject]@{ Property='Enrolments on device';     Value="$($act.TotalFound) total (showing the active one)" },
        [pscustomobject]@{ Property='MDM certificate';          Value="$($i.Certificate.Subject)" },
        [pscustomobject]@{ Property='Certificate expires';      Value="$($i.Certificate.NotAfter)" },
        [pscustomobject]@{ Property='IME service';              Value="$($i.ImeService.Status)" },
        [pscustomobject]@{ Property='IME version';              Value=$i.ImeVersion },
        [pscustomobject]@{ Property='Policy CSP areas applied'; Value="$(@($i.PolicyAreas).Count) areas" },
        [pscustomobject]@{ Property='IME log folder';           Value=$i.LogFolder }
    )
    try {
        Set-DxItems -Grid $UI.gridIntune -Items $rows -Label 'gridIntune' | Out-Null
        $issues = @($i.Issues)
        if ($issues.Count -eq 0) { $issues = @('No MDM problems detected on this device.') }
        Set-DxItems -Grid $UI.lstIntuneIssues -Items $issues -Label 'lstIntuneIssues' | Out-Null
        Set-DxItems -Grid $UI.gridMdmTasks -Items $i.Tasks -Label 'gridMdmTasks' | Out-Null
        $nApps = Set-DxItems -Grid $UI.gridWin32 -Items $i.Win32Apps -Label 'gridWin32'
        Set-DxItems -Grid $UI.gridPsScripts -Items $i.Scripts -Label 'gridPsScripts' | Out-Null
        Set-DxItems -Grid $UI.gridRemediations -Items $i.Remediations -Label 'gridRemediations' | Out-Null
        Set-DxItems -Grid $UI.gridMdmEvents -Items $i.MdmEvents -Label 'gridMdmEvents' -Cap 500 | Out-Null
        Set-DxItems -Grid $UI.gridImeLogs -Items $script:Data.IntuneLogs -Label 'gridImeLogs' -Cap 500 | Out-Null
        if ($nApps -eq 0) { $UI.lblWin32.Text = 'WIN32 APP ENFORCEMENT STATE  -  none assigned to this device or user' }
        else { $UI.lblWin32.Text = "WIN32 APP ENFORCEMENT STATE  ($nApps app(s))" }
        $UI.lblPsScripts.Text    = "PLATFORM POWERSHELL SCRIPTS  ($(@($i.Scripts).Count) assigned)"
        $UI.lblRemediations.Text = "REMEDIATIONS  ($(@($i.Remediations).Count) assigned)"
        if (@($i.SectionErrors).Count -gt 0) {
            Write-DxConsole "Intune collector reported $(@($i.SectionErrors).Count) note(s) - see Findings."
        }
    }
    catch { Write-DxCrash -Context 'Update-DxIntuneTab' -ErrorObject $_ | Out-Null }
}

$script:GpoRendered = $false
$script:GpoSettingCap = 800

function Update-DxGpoTab {
    $g = $script:Data.Gpo
    $script:GpoRendered = $false
    if (-not $g) { $UI.lblGpoSummary.Text = 'No Group Policy data yet.'; return }
    try {
        $errs = @($g.Conflicts | Where-Object { $_.Severity -eq 'Error' }).Count
        $UI.lblGpoSummary.Text = "$(@($g.AppliedGpos).Count) applied | $(@($g.DeniedGpos).Count) filtered | $(@($g.Settings).Count) settings | $(@($g.Conflicts).Count) risk item(s), $errs need attention"
        if (@($g.SectionErrors).Count -gt 0) {
            $UI.lblGpoSummary.Text += "   |   $(@($g.SectionErrors).Count) collector note(s)"
            foreach ($e in @($g.SectionErrors)) { Write-DxConsole "GPO $e" }
        }
    }
    catch { Write-DxCrash -Context 'Update-DxGpoTab summary' -ErrorObject $_ | Out-Null }
    if ($UI.tabs.SelectedItem -eq $UI.tabPolicy) { Show-DxGpoGrids }
}

function Show-DxGpoGrids {
    if ($script:GpoRendered) { return }
    $g = $script:Data.Gpo
    if (-not $g) { return }
    $script:GpoRendered = $true
    Set-DxStatus -Text 'Rendering Group Policy results...' -Busy
    try {
        $conf = @($g.Conflicts)
        try { $conf = @($conf | Sort-Object @{ Expression = { switch ("$($_.Severity)") { 'Error'{0} 'Warning'{1} default{2} } } }) } catch { }
        Set-DxItems -Grid $UI.gridConflicts -Items $conf -Label 'gridConflicts' | Out-Null
        $applied = @($g.AppliedGpos)
        try { $applied = @($applied | Sort-Object Scope, Order) } catch { }
        Set-DxItems -Grid $UI.gridGpoApplied -Items $applied -Label 'gridGpoApplied' | Out-Null
        Set-DxItems -Grid $UI.gridGpoDenied -Items $g.DeniedGpos -Label 'gridGpoDenied' | Out-Null
        $cse = @($g.Extensions)
        try { $cse = @($cse | Sort-Object @{ Expression = { if ("$($_.Status)" -eq 'Success') {1} else {0} } }) } catch { }
        Set-DxItems -Grid $UI.gridCse -Items $cse -Label 'gridCse' | Out-Null
        Set-DxItems -Grid $UI.gridGpEvents -Items $g.Events -Label 'gridGpEvents' -Cap 1000 | Out-Null
        $shown = Set-DxItems -Grid $UI.gridGpoSettings -Items $g.Settings -Label 'gridGpoSettings' -Cap $script:GpoSettingCap
        $UI.lblGpoRows.Text = "showing $shown of $(@($g.Settings).Count) (search to narrow)"
    }
    catch {
        Write-DxCrash -Context 'Show-DxGpoGrids' -ErrorObject $_ | Out-Null
        Write-DxConsole "Group Policy render error (logged): $($_.Exception.Message)"
    }
    finally { Set-DxStatus -Text 'Ready.' -Done }
}

function Find-DxGpoSettings {
    $g = $script:Data.Gpo
    if (-not $g) { return }
    try {
        $q = $UI.txtGpoFind.Text
        $all = @($g.Settings)
        if ([string]::IsNullOrWhiteSpace($q)) { $hits = $all }
        else {
            $rx = [regex]::Escape($q)
            $hits = @($all | Where-Object {
                $_.Setting -match $rx -or $_.KeyName -match $rx -or $_.ValueName -match $rx -or $_.GPO -match $rx })
        }
        $shown = Set-DxItems -Grid $UI.gridGpoSettings -Items $hits -Label 'gridGpoSettings' -Cap $script:GpoSettingCap
        $UI.lblGpoRows.Text = "showing $shown of $(@($hits).Count) match(es), $(@($all).Count) total"
    }
    catch { Write-DxCrash -Context 'Find-DxGpoSettings' -ErrorObject $_ | Out-Null }
}

function Update-DxSysTab {
    $d = $script:Data.SysDiag
    if (-not $d) { return }
    try {
        Set-DxItems -Grid $UI.gridConn -Items $d.Connectivity -Label 'gridConn' | Out-Null
        Set-DxItems -Grid $UI.gridNetConn -Items $d.Connectivity -Label 'gridNetConn' | Out-Null
        Set-DxItems -Grid $UI.gridDisks -Items $d.Volumes -Label 'gridDisks' | Out-Null
        Set-DxItems -Grid $UI.gridDevices -Items $d.ProblemDevices -Label 'gridDevices' | Out-Null
        Set-DxItems -Grid $UI.gridServices -Items $d.StoppedAutoServices -Label 'gridServices' | Out-Null
        Set-DxItems -Grid $UI.gridStability -Items $d.BugChecks -Label 'gridStability' | Out-Null
        Set-DxItems -Grid $UI.gridCrashes -Items $d.AppCrashes -Label 'gridCrashes' -Cap 500 | Out-Null
        Set-DxItems -Grid $UI.gridUpdates -Items $d.RecentUpdates -Label 'gridUpdates' | Out-Null
        Set-DxItems -Grid $UI.gridWuErrors -Items $d.UpdateErrors -Label 'gridWuErrors' -Cap 500 | Out-Null
        Show-DxHBars -Canvas $UI.cvDisks -Data (Get-DxDiskChartData -Snapshot $script:Data.Snapshot) -LabelW 140
    }
    catch { Write-DxCrash -Context 'Update-DxSysTab' -ErrorObject $_ | Out-Null }
    if ($d.PendingReboot.Pending) {
        $UI.lblRebootPending.Text = "Reboot pending: $((@($d.PendingReboot.Reasons)) -join ' | ')"
        $UI.kpiReboot.Text = 'reboot pending'
    } else {
        $UI.lblRebootPending.Text = ''
        $UI.kpiReboot.Text = 'no reboot pending'
    }
}

function Redraw-DxAllCharts {
    try {
        Update-DxDashboardCharts
        if ($script:Data.CertSummary) { Show-DxHBars -Canvas $UI.cvCertPurpose -Data $script:Data.CertSummary.PurposeChart -LabelW 175 }
        if ($script:Data.Firewall) { Show-DxHBars -Canvas $UI.cvFwRules -Data $script:Data.Firewall.RuleChart -LabelW 110 }
        if ($script:Data.Dns) { Show-DxHBars -Canvas $UI.cvDnsProbe -Data $script:Data.Dns.ProbeChart -LabelW 190 }
        Show-DxHBars -Canvas $UI.cvDisks -Data (Get-DxDiskChartData -Snapshot $script:Data.Snapshot) -LabelW 140
    }
    catch { }
}

# =============================================================================
#  Reusable scrollable text window (diagnostics, dumps)
# =============================================================================
function Show-DxTextWindow {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Text,
        [string]$ApplyLabel = '',
        [scriptblock]$ApplyAction = $null
    )
    try {
        $tw = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Diagnostic" Height="740" Width="1020" MinHeight="400" MinWidth="600"
        WindowStartupLocation="CenterOwner" Background="{DynamicResource DxWindowBg}" FontFamily="Segoe UI" FontSize="12">
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border Grid.Row="0" Background="{DynamicResource DxConsoleBg}" Padding="18,13">
      <TextBlock x:Name="tTitle" Foreground="White" FontSize="16" FontWeight="SemiBold"/>
    </Border>
    <Border Grid.Row="1" Margin="10" Background="{DynamicResource DxConsoleBg}" CornerRadius="8">
      <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
        <TextBox x:Name="tBody" IsReadOnly="True" BorderThickness="0" Background="{DynamicResource DxConsoleBg}"
                 Foreground="{DynamicResource DxConsoleFg}" Padding="13" FontFamily="Consolas" FontSize="11.5" TextWrapping="NoWrap"/>
      </ScrollViewer>
    </Border>
    <Border Grid.Row="2" Background="{DynamicResource DxCardBg}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="0,1,0,0" Padding="12,9">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="tApply" Content="Apply" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxOk}"
                Foreground="White" BorderThickness="0" Cursor="Hand" Visibility="Collapsed"/>
        <Button x:Name="tCopy" Content="Copy all" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxGhost}"
                Foreground="White" BorderThickness="0" Cursor="Hand"/>
        <Button x:Name="tSave" Content="Save to file" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxGhost}"
                Foreground="White" BorderThickness="0" Cursor="Hand"/>
        <Button x:Name="tClose" Content="Close" Padding="20,7" Background="{DynamicResource DxConsoleBg}"
                Foreground="White" BorderThickness="0" Cursor="Hand"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
'@
        [xml]$tx = $tw
        $tr = New-Object System.Xml.XmlNodeReader $tx
        $twin = [Windows.Markup.XamlReader]::Load($tr)
        $twin.Owner = $window
        # Resource lookup does NOT walk the Owner chain, and there is no
        # Application object here, so a child window sees an empty dictionary
        # and every DynamicResource in its XAML silently resolves to nothing.
        # Sharing the parent dictionary makes it theme with the main window.
        $twin.Resources = $window.Resources
        $T = @{}
        foreach ($node in $tx.SelectNodes("//*[@*[local-name()='Name']]")) {
            $n = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
            if ([string]::IsNullOrEmpty($n)) { $n = $node.GetAttribute('Name') }
            if ($n) { $c = $twin.FindName($n); if ($c) { $T[$n] = $c } }
        }
        $twin.Title = $Title
        $T.tTitle.Text = $Title
        $T.tBody.Text = $Text
        $script:TextWindowPayload = $Text
        if ($ApplyAction -and $ApplyLabel) {
            $T.tApply.Content = $ApplyLabel
            $T.tApply.Visibility = 'Visible'
            $script:TextWindowApply = $ApplyAction
            $T.tApply.Add_Click({
                try { & $script:TextWindowApply } catch { Write-DxCrash -Context 'TextWindow apply' -ErrorObject $_ | Out-Null }
                $twin.Close()
            })
        }
        $T.tCopy.Add_Click({ try { [Windows.Clipboard]::SetText([string]$script:TextWindowPayload) } catch { } })
        $T.tSave.Add_Click({
            try {
                $dlg = New-Object Windows.Forms.SaveFileDialog
                $dlg.Filter = 'Text file (*.txt)|*.txt'
                $dlg.FileName = "Sysadmin-diagnostic-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').txt"
                $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
                if ($dlg.ShowDialog() -eq 'OK') {
                    Set-Content -Path $dlg.FileName -Value $script:TextWindowPayload -Encoding UTF8
                    Write-DxConsole "Diagnostic saved: $($dlg.FileName)"
                }
            } catch { }
        })
        $T.tClose.Add_Click({ $twin.Close() })
        $null = $twin.ShowDialog()
    }
    catch {
        Write-DxCrash -Context 'Show-DxTextWindow' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not open the diagnostic window: $($_.Exception.Message)"
    }
}

# =============================================================================
#  Full event detail window
# =============================================================================
function Show-DxEventDetailWindow {
    param($EventRow)
    if (-not $EventRow) { Set-DxStatus -Text 'Select an event row first.' -Done; return }
    try {
        Set-DxStatus -Text 'Reading full event detail...' -Busy
        $kb = Resolve-DxEventGuidance -ProviderName $EventRow.Provider -EventId $EventRow.Id -Level $EventRow.Level -Message $EventRow.Message
        $det = Get-DxEventFullDetail -LogName $EventRow.LogName -RecordId $EventRow.RecordId
        Set-DxStatus -Text 'Ready.' -Done

        $detailXaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Event detail" Height="820" Width="1180" MinHeight="450" MinWidth="700"
        WindowStartupLocation="CenterOwner" Background="{DynamicResource DxWindowBg}" FontFamily="Segoe UI" FontSize="12">
  <Grid>
    <Grid.RowDefinitions><RowDefinition Height="Auto"/><RowDefinition Height="*"/><RowDefinition Height="Auto"/></Grid.RowDefinitions>
    <Border x:Name="hdr" Grid.Row="0" Background="{DynamicResource DxConsoleBg}" Padding="18,13">
      <StackPanel>
        <TextBlock x:Name="dTitle" Foreground="White" FontSize="16" FontWeight="SemiBold" TextWrapping="Wrap"/>
        <TextBlock x:Name="dMeta" Foreground="{DynamicResource DxSpotMuted}" FontSize="11.5" Margin="0,5,0,0" TextWrapping="Wrap"/>
      </StackPanel>
    </Border>
    <TabControl Grid.Row="1" Margin="10" Background="{DynamicResource DxTabStripBg}" BorderBrush="{DynamicResource DxCardBorder}">
      <TabItem Header="Summary">
        <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="14">
          <StackPanel>
            <TextBlock Text="RENDERED MESSAGE" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}" Margin="0,0,0,6"/>
            <Border Background="{DynamicResource DxSubtle}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="1" CornerRadius="8" Padding="11">
              <TextBlock x:Name="dMessage" TextWrapping="Wrap" FontFamily="Consolas" FontSize="11.5"/>
            </Border>
            <TextBlock Text="DIAGNOSIS" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}" Margin="0,14,0,6"/>
            <TextBlock x:Name="dDiag" TextWrapping="Wrap" FontWeight="SemiBold" FontSize="13"/>
            <TextBlock Text="LIKELY CAUSE" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}" Margin="0,12,0,4"/>
            <TextBlock x:Name="dCause" TextWrapping="Wrap"/>
            <TextBlock Text="IMPACT" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}" Margin="0,12,0,4"/>
            <TextBlock x:Name="dImpact" TextWrapping="Wrap"/>
            <TextBlock Text="RESOLUTION STEPS" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}" Margin="0,12,0,6"/>
            <ItemsControl x:Name="dSteps">
              <ItemsControl.ItemTemplate><DataTemplate>
                <Border Background="{DynamicResource DxSubtle}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="1" CornerRadius="7" Padding="10,7" Margin="0,0,0,5">
                  <TextBlock Text="{Binding}" TextWrapping="Wrap"/>
                </Border>
              </DataTemplate></ItemsControl.ItemTemplate>
            </ItemsControl>
            <TextBlock Text="COMMANDS" FontSize="11" FontWeight="SemiBold" Foreground="{DynamicResource DxMuted}" Margin="0,10,0,6"/>
            <ListBox x:Name="dCommands" Background="{DynamicResource DxConsoleBg}" Foreground="{DynamicResource DxSpotFg}" BorderThickness="0" FontFamily="Consolas" FontSize="11.5" MaxHeight="190"/>
          </StackPanel>
        </ScrollViewer>
      </TabItem>
      <TabItem Header="Event data fields">
        <DataGrid x:Name="dProps" Margin="6" AutoGenerateColumns="False" IsReadOnly="True" GridLinesVisibility="None"
                  RowBackground="{DynamicResource DxCardBg}" HeadersVisibility="Column" BorderBrush="{DynamicResource DxCardBorder}" FontSize="11.5">
          <DataGrid.Columns>
            <DataGridTextColumn Header="Field" Binding="{Binding Name}" Width="250"/>
            <DataGridTextColumn Header="Value" Binding="{Binding Value}" Width="*"/>
          </DataGrid.Columns>
        </DataGrid>
      </TabItem>
      <TabItem Header="Raw XML">
        <Border Margin="6" Background="{DynamicResource DxConsoleBg}" CornerRadius="8">
          <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto">
            <TextBox x:Name="dXml" IsReadOnly="True" BorderThickness="0" Background="{DynamicResource DxConsoleBg}" Foreground="{DynamicResource DxConsoleFg}"
                     Padding="13" FontFamily="Consolas" FontSize="11.5" TextWrapping="NoWrap"/>
          </ScrollViewer>
        </Border>
      </TabItem>
    </TabControl>
    <Border Grid.Row="2" Background="{DynamicResource DxCardBg}" BorderBrush="{DynamicResource DxCardBorder}" BorderThickness="0,1,0,0" Padding="12,9">
      <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
        <Button x:Name="dCopy" Content="Copy everything" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxGhost}" Foreground="White" BorderThickness="0" Cursor="Hand"/>
        <Button x:Name="dCopyXml" Content="Copy XML" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxGhost}" Foreground="White" BorderThickness="0" Cursor="Hand"/>
        <Button x:Name="dDocs" Content="Microsoft docs" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxAccent}" Foreground="White" BorderThickness="0" Cursor="Hand"/>
        <Button x:Name="dEvtVwr" Content="Open Event Viewer" Padding="13,7" Margin="0,0,8,0" Background="{DynamicResource DxGhost}" Foreground="White" BorderThickness="0" Cursor="Hand"/>
        <Button x:Name="dClose" Content="Close" Padding="20,7" Background="{DynamicResource DxConsoleBg}" Foreground="White" BorderThickness="0" Cursor="Hand"/>
      </StackPanel>
    </Border>
  </Grid>
</Window>
'@
        [xml]$dx = $detailXaml
        $dr = New-Object System.Xml.XmlNodeReader $dx
        $dwin = [Windows.Markup.XamlReader]::Load($dr)
        $dwin.Owner = $window
        # Resource lookup does NOT walk the Owner chain, and there is no
        # Application object here, so a child window sees an empty dictionary
        # and every DynamicResource in its XAML silently resolves to nothing.
        # Sharing the parent dictionary makes it theme with the main window.
        $dwin.Resources = $window.Resources
        $D = @{}
        foreach ($node in $dx.SelectNodes("//*[@*[local-name()='Name']]")) {
            $n = $node.GetAttribute('Name', 'http://schemas.microsoft.com/winfx/2006/xaml')
            if ([string]::IsNullOrEmpty($n)) { $n = $node.GetAttribute('Name') }
            if ($n) { $c = $dwin.FindName($n); if ($c) { $D[$n] = $c } }
        }
        $hdrColor = switch ("$($EventRow.Level)") {
            'Critical'{(Get-DxColor 'DxSevCritFg')} 'Error'{(Get-DxColor 'DxSevErrFg')} 'Warning'{(Get-DxColor 'DxSevWarnFg')} 'Information'{(Get-DxColor 'DxSevInfoFg')} default{(Get-DxColor 'DxInk')}
        }
        try { $D.hdr.Background = New-DxBrush $hdrColor } catch { }
        $D.dTitle.Text = "[$($EventRow.Level)]  $($EventRow.Provider)  -  Event ID $($EventRow.Id)"
        $D.dMeta.Text = "Logged $($EventRow.TimeCreated)   |   Log: $($EventRow.LogName)   |   Record: $($EventRow.RecordId)   |   Machine: $($EventRow.Machine)   |   Task: $($EventRow.Task)   |   PID: $($EventRow.ProcessId)"
        $msgText = $EventRow.Message
        if ($det.Found -and $det.Message) { $msgText = $det.Message }
        $D.dMessage.Text = $msgText
        $D.dDiag.Text = $kb.Title
        $D.dCause.Text = $kb.Cause
        $D.dImpact.Text = $kb.Impact
        $steps = @(); $n = 1
        foreach ($st in @($kb.Steps)) { $steps += "$n.  $st"; $n++ }
        Set-DxItems -Grid $D.dSteps -Items $steps -Label 'dSteps' | Out-Null
        Set-DxItems -Grid $D.dCommands -Items $kb.Commands -Label 'dCommands' | Out-Null
        Set-DxItems -Grid $D.dProps -Items $det.Properties -Label 'dProps' | Out-Null
        if ($det.Found) { $D.dXml.Text = $det.XmlPretty }
        else { $D.dXml.Text = "Raw XML unavailable.`r`n$($det.Error)" }
        $script:DetailPayload = [pscustomobject]@{ Row=$EventRow; Kb=$kb; Detail=$det }
        $D.dClose.Add_Click({ $dwin.Close() })
        $D.dDocs.Add_Click({ if ($script:DetailPayload.Kb.Docs) { Start-Process $script:DetailPayload.Kb.Docs } })
        $D.dEvtVwr.Add_Click({ Open-DxConsole -File 'eventvwr.msc' -Label 'Event Viewer' })
        $D.dCopyXml.Add_Click({ try { [Windows.Clipboard]::SetText([string]$script:DetailPayload.Detail.XmlPretty) } catch { } })
        $D.dCopy.Add_Click({
            try {
                $p = $script:DetailPayload
                $sb = New-Object System.Text.StringBuilder
                [void]$sb.AppendLine("EVENT    : [$($p.Row.Level)] $($p.Row.Provider) - ID $($p.Row.Id)")
                [void]$sb.AppendLine("TIME     : $($p.Row.TimeCreated)")
                [void]$sb.AppendLine("LOG      : $($p.Row.LogName)   RECORD: $($p.Row.RecordId)")
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine("MESSAGE  :`r`n$($p.Row.Message)")
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine("DIAGNOSIS: $($p.Kb.Title)")
                [void]$sb.AppendLine("CAUSE    : $($p.Kb.Cause)")
                [void]$sb.AppendLine("IMPACT   : $($p.Kb.Impact)")
                [void]$sb.AppendLine('RESOLUTION:')
                $i = 1
                foreach ($st in @($p.Kb.Steps)) { [void]$sb.AppendLine("  $i. $st"); $i++ }
                [void]$sb.AppendLine('COMMANDS:')
                foreach ($c in @($p.Kb.Commands)) { [void]$sb.AppendLine("  $c") }
                [void]$sb.AppendLine("DOCS     : $($p.Kb.Docs)")
                [void]$sb.AppendLine('')
                [void]$sb.AppendLine('RAW XML:')
                [void]$sb.AppendLine($p.Detail.XmlPretty)
                [Windows.Clipboard]::SetText($sb.ToString())
            } catch { }
        })
        $null = $dwin.ShowDialog()
    }
    catch {
        Set-DxStatus -Text 'Ready.' -Done
        Write-DxCrash -Context 'Show-DxEventDetailWindow' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not open the event detail window: $($_.Exception.Message)"
    }
}

# =============================================================================
#  Universal collector diagnostic  -  runs IN PROCESS, no runspace
# =============================================================================
function Show-DxCollectorDiagnostic {
    try {
        Set-DxStatus -Text 'Running collector diagnostic in process...' -Busy
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine('Sys@dmin - collector diagnostic')
        [void]$sb.AppendLine("Host      : $env:COMPUTERNAME   User: $env:USERNAME   Elevated: $script:IsElevated")
        [void]$sb.AppendLine("PowerShell: $($PSVersionTable.PSVersion)   OS: $([Environment]::OSVersion.Version)")
        [void]$sb.AppendLine("AppRoot   : $script:AppRoot   Compiled: $script:IsCompiled")
        [void]$sb.AppendLine("Time      : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
        [void]$sb.AppendLine(('=' * 78))

        [void]$sb.AppendLine("`r`n--- 1. Modules (UI thread) ---")
        foreach ($m in @('DnsClient','NetTCPIP','NetSecurity','NetAdapter')) {
            $avail = Get-Module -Name $m -ListAvailable -ErrorAction SilentlyContinue
            $imported = Get-Module -Name $m -ErrorAction SilentlyContinue
            [void]$sb.AppendLine(("  {0,-12} available={1,-5} imported={2}" -f $m, [bool]$avail, [bool]$imported))
        }
        if ($script:DxModuleReport) {
            [void]$sb.AppendLine("  Engine import - loaded: $((@($script:DxModuleReport.Loaded)) -join ', ')")
            foreach ($f in @($script:DxModuleReport.Failed)) { [void]$sb.AppendLine("  FAILED: $f") }
        }

        # each collector run in process, individually timed and trapped
        $collectors = @(
            @{ Name='Get-DxFirewallState'; Key='Firewall'; Probe={ Get-DxFirewallState } },
            @{ Name='Get-DxDnsState';      Key='Dns';      Probe={ Get-DxDnsState } },
            @{ Name='Get-DxIntuneState';   Key='Intune';   Probe={ Get-DxIntuneState } },
            @{ Name='Get-DxGpoState';      Key='Gpo';      Probe={ Get-DxGpoState } }
        )
        $results = @{}
        foreach ($c in $collectors) {
            [void]$sb.AppendLine("`r`n--- $($c.Name) IN PROCESS ---")
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $obj = $null; $err = ''; $stack = ''
            try { $obj = & $c.Probe }
            catch {
                $err = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
                if ($_.ScriptStackTrace) { $stack = ($_.ScriptStackTrace -split "`n")[0].Trim() }
            }
            $sw.Stop()
            [void]$sb.AppendLine("  elapsed: $([int]$sw.ElapsedMilliseconds) ms")
            if ($err) {
                [void]$sb.AppendLine("  THREW: $err")
                if ($stack) { [void]$sb.AppendLine("  at   : $stack") }
            }
            elseif (-not $obj) { [void]$sb.AppendLine('  returned NULL') }
            else {
                $results[$c.Key] = $obj
                foreach ($p in $obj.PSObject.Properties) {
                    $v = $p.Value
                    if ($null -eq $v) { [void]$sb.AppendLine(("  {0,-18} : null" -f $p.Name)); continue }
                    if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
                        [void]$sb.AppendLine(("  {0,-18} : {1} item(s)" -f $p.Name, (Get-DxCount $v)))
                    } else {
                        $s = "$v"
                        if ($s.Length -gt 70) { $s = $s.Substring(0,70) + '...' }
                        [void]$sb.AppendLine(("  {0,-18} : {1}" -f $p.Name, $s))
                    }
                }
                foreach ($e in @($obj.SectionErrors)) { [void]$sb.AppendLine("  SECTION ERROR $e") }
            }
        }

        [void]$sb.AppendLine("`r`n--- What the UI currently holds ---")
        [void]$sb.AppendLine("  Firewall rules : $(Get-DxCount $script:Data.Firewall.Rules)   grid=$($UI.gridFwRules.Items.Count)")
        [void]$sb.AppendLine("  DNS servers    : $(Get-DxCount $script:Data.Dns.Servers)   grid=$($UI.gridDnsServers.Items.Count)")
        [void]$sb.AppendLine("  Win32 apps     : $(Get-DxCount $script:Data.Intune.Win32Apps)   grid=$($UI.gridWin32.Items.Count)")
        [void]$sb.AppendLine("  GPO applied    : $(Get-DxCount $script:Data.Gpo.AppliedGpos)   grid=$($UI.gridGpoApplied.Items.Count)")

        [void]$sb.AppendLine("`r`n--- Verdict ---")
        $anyInproc = ((Get-DxCount $results['Firewall'].Rules) + (Get-DxCount $results['Dns'].Servers) +
                      (Get-DxCount $results['Intune'].Win32Apps) + (Get-DxCount $results['Gpo'].AppliedGpos))
        $anyUi = ((Get-DxCount $script:Data.Firewall.Rules) + (Get-DxCount $script:Data.Dns.Servers) +
                  (Get-DxCount $script:Data.Intune.Win32Apps) + (Get-DxCount $script:Data.Gpo.AppliedGpos))
        if ($anyInproc -gt 0 -and $anyUi -eq 0) {
            [void]$sb.AppendLine('  Collection WORKS in process but the background scan delivered nothing.')
            [void]$sb.AppendLine('  -> Runspace fault. Use "Apply in-process result" below as an immediate workaround.')
        } elseif ($anyInproc -eq 0) {
            [void]$sb.AppendLine('  Collectors return no data even in process. See the section errors above -')
            [void]$sb.AppendLine('  on a cloud-only device, empty GPO and Win32 results can be entirely correct.')
        } else {
            [void]$sb.AppendLine('  Both in-process and UI data are populated - the tabs should be showing data.')
        }

        Set-DxStatus -Text 'Ready.' -Done
        $script:DiagInproc = $results
        Show-DxTextWindow -Title 'Collector diagnostic' -Text $sb.ToString() -ApplyLabel 'Apply in-process result' -ApplyAction {
            $r = $script:DiagInproc
            if ($r) {
                if ($r['Firewall']) { $script:Data.Firewall = $r['Firewall']; Update-DxFirewallTab }
                if ($r['Dns'])      { $script:Data.Dns      = $r['Dns'];      Update-DxDnsTab }
                if ($r['Intune'])   { $script:Data.Intune   = $r['Intune'];   Update-DxIntuneTab }
                if ($r['Gpo'])      { $script:Data.Gpo      = $r['Gpo'];      Update-DxGpoTab; Show-DxGpoGrids }
                Update-DxNetSummary
                Write-DxConsole 'Applied in-process collector results to the tabs.'
            }
        }
    }
    catch {
        Set-DxStatus -Text 'Ready.' -Done
        Write-DxCrash -Context 'Show-DxCollectorDiagnostic' -ErrorObject $_ | Out-Null
        Write-DxConsole "Collector diagnostic failed: $($_.Exception.Message)"
    }
}

# =============================================================================
#  Scans
# =============================================================================
function Invoke-DxEventScan {
    $hours = Get-DxSelectedHours; $levels = Get-DxSelectedLevels; $logs = Get-DxSelectedLogs
    $script = @'
$ev  = Get-DxEvents -LogNames $DxLogs -Levels $DxLevels -Hours $DxHours -MaxPerLog 2000
$sum = Get-DxEventSummary -Events $ev -Top 60
$st  = Get-DxEventStats -Events $ev
[pscustomobject]@{ Events=$ev; Summary=$sum; Stats=$st }
'@
    Start-DxUiJob -ScriptText $script -StatusText "Reading event logs (last $hours h)..." `
        -Arguments @{ DxLogs=$logs; DxLevels=$levels; DxHours=$hours } -OnComplete {
            param($r)
            $res = Get-DxJobResult -Raw $r -Expect @('Events','Summary','Stats')
            if ($res) {
                $script:Data.Events = @($res.Events)
                $script:Data.EventSummary = @($res.Summary)
                $script:Data.EventStats = $res.Stats
            }
            $logNames = @('All logs') + (@($script:Data.Events | Select-Object -ExpandProperty LogName -Unique))
            Set-DxItems -Grid $UI.cboLog -Items $logNames -Label 'cboLog' | Out-Null
            if (-not $UI.cboLog.Text) { $UI.cboLog.Text = 'All logs' }
            Update-DxEventGrid
            Update-DxDashboard
            Write-DxConsole "Event scan complete: $(@($script:Data.Events).Count) events, $(@($script:Data.EventSummary).Count) signatures."
        }
}

function Invoke-DxNetworkScan {
    $script = @'
$fw  = Get-DxFirewallState
$dns = Get-DxDnsState
$ad  = Get-DxNetAdapters
[pscustomobject]@{ Firewall=$fw; Dns=$dns; Adapters=$ad }
'@
    Start-DxUiJob -ScriptText $script -StatusText 'Analysing firewall, DNS and adapters...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Firewall','Dns','Adapters')
        if (-not $res) { Write-DxConsole 'Network scan returned no data.'; return }
        $script:Data.Firewall = $res.Firewall
        $script:Data.Dns = $res.Dns
        $script:Data.Adapters = @($res.Adapters)
        Update-DxFirewallTab
        Update-DxDnsTab
        Set-DxItems -Grid $UI.gridAdapters -Items $script:Data.Adapters -Label 'gridAdapters' | Out-Null
        Update-DxNetSummary
        Write-DxConsole "Network scan complete: $(@($res.Firewall.Rules).Count) firewall rule(s), $(@($res.Dns.Servers).Count) DNS adapter(s)."
    }
}

function Invoke-DxCertScan {
    $includeCa = [bool]$UI.chkCertCa.IsChecked
    $script = @'
$c = Get-DxCertificates -IncludeCaStores:$DxIncludeCa
[pscustomobject]@{ Certs=$c; Summary=(Get-DxCertSummary -Certs $c); Findings=(Get-DxCertFindings -Certs $c) }
'@
    Start-DxUiJob -ScriptText $script -StatusText 'Reading certificate stores...' `
        -Arguments @{ DxIncludeCa=$includeCa } -OnComplete {
            param($r)
            $res = Get-DxJobResult -Raw $r -Expect @('Certs','Summary','Findings')
            if ($res) {
                $script:Data.Certs = @($res.Certs)
                $script:Data.CertSummary = $res.Summary
                $script:Data.CertFindings = @($res.Findings)
                Update-DxCertTab
                Write-DxConsole "Certificate scan complete: $(@($res.Certs).Count) certificate(s), $($res.Summary.Expired) expired."
            }
        }
}

function Invoke-DxFullScan {
    $hours = Get-DxSelectedHours; $levels = Get-DxSelectedLevels; $logs = Get-DxSelectedLogs
    $incCa = [bool]$UI.chkCertCa.IsChecked
    $script = @'
$snap   = Get-DxSystemSnapshot
$ev     = Get-DxEvents -LogNames $DxLogs -Levels $DxLevels -Hours $DxHours -MaxPerLog 2000
$sum    = Get-DxEventSummary -Events $ev -Top 60
$st     = Get-DxEventStats -Events $ev
$certs  = Get-DxCertificates -IncludeCaStores:$DxIncludeCa
$fw     = Get-DxFirewallState
$dns    = Get-DxDnsState
$ad     = Get-DxNetAdapters
$intune = Get-DxIntuneState
$imelog = Get-DxIntuneLogFindings
$sys    = Get-DxSystemDiagnostics
$gpo    = Get-DxGpoState
$pol    = Get-DxPolicyState -Gpo $gpo
$adv    = Get-DxSystemHealthAdvanced -Hours $DxHours
$ideep  = Get-DxIntuneDeep -Intune $intune
$health = Get-DxHealthScore -Snapshot $snap -EventStats $st -Intune $intune -Gpo $gpo -SysDiag $sys -Certs $certs -Firewall $fw -Dns $dns
[pscustomobject]@{
    Snapshot=$snap; Events=$ev; Summary=$sum; Stats=$st
    Intune=$intune; IntuneLogs=$imelog; SysDiag=$sys; Gpo=$gpo; Policy=$pol; Adv=$adv
    IntuneDeep=$ideep; Health=$health
    Certs=$certs; CertSummary=(Get-DxCertSummary -Certs $certs); CertFindings=(Get-DxCertFindings -Certs $certs)
    Firewall=$fw; Dns=$dns; Adapters=$ad
}
'@
    Write-DxConsole 'Full scan started. Firewall, DNS, Group Policy, effective policy, hardware and posture checks can take 90-180 seconds.'
    Start-DxUiJob -ScriptText $script -StatusText 'Running full diagnostics...' `
        -Arguments @{ DxLogs=$logs; DxLevels=$levels; DxHours=$hours; DxIncludeCa=$incCa } -OnComplete {
            param($r)
            $res = Get-DxJobResult -Raw $r -Expect @('Snapshot','Events','Dns','Firewall','Policy')
            if (-not $res) { Write-DxConsole 'Full scan returned no data.'; return }
            $script:Data.Snapshot = $res.Snapshot
            if ($res.Snapshot -and $res.Snapshot.SerialNumber) { Set-DxWindowTitle -Serial "$($res.Snapshot.SerialNumber)" }
            $script:Data.Events = @($res.Events)
            $script:Data.EventSummary = @($res.Summary)
            $script:Data.EventStats = $res.Stats
            $script:Data.Intune = $res.Intune
            $script:Data.IntuneLogs = @($res.IntuneLogs)
            $script:Data.SysDiag = $res.SysDiag
            $script:Data.Gpo = $res.Gpo
            $script:Data.Policy = $res.Policy
            $script:Data.Adv = $res.Adv
            $script:Data.IntuneDeep = $res.IntuneDeep
            $script:Data.Health = $res.Health
            $script:Data.Certs = @($res.Certs)
            $script:Data.CertSummary = $res.CertSummary
            $script:Data.CertFindings = @($res.CertFindings)
            $script:Data.Firewall = $res.Firewall
            $script:Data.Dns = $res.Dns
            $script:Data.Adapters = @($res.Adapters)

            $logNames = @('All logs') + (@($script:Data.Events | Select-Object -ExpandProperty LogName -Unique))
            Set-DxItems -Grid $UI.cboLog -Items $logNames -Label 'cboLog' | Out-Null
            if (-not $UI.cboLog.Text) { $UI.cboLog.Text = 'All logs' }

            Update-DxEventGrid
            Update-DxDashboard
            Update-DxFirewallTab
            Update-DxDnsTab
            Set-DxItems -Grid $UI.gridAdapters -Items $script:Data.Adapters -Label 'gridAdapters' | Out-Null
            Update-DxNetSummary
            Update-DxCertTab
            Update-DxIntuneTab
            Update-DxGpoTab
            Update-DxPolicyTab
            Update-DxSysTab
            Update-DxAdvTab
            Update-DxIntuneDeepTab
            Write-DxConsole "Full scan complete. Health score $($res.Health.Score)/100 ($($res.Health.Grade))."
            if ($res.Policy) {
                Write-DxConsole "Effective policy: $($res.Policy.Counts.Mdm) Policy CSP setting(s) across $($res.Policy.Counts.Areas) area(s), $($res.Policy.Counts.Gpo) GPO setting(s), $($res.Policy.Counts.Legacy) registry policy value(s)."
            } else {
                Write-DxConsole 'Effective policy returned nothing - open the Policy tab and click "Analyse policy" to collect it on its own.'
            }
        }
}

function Invoke-DxAction {
    param([string]$Name, [string]$Label, [switch]$Confirm)
    if ($Confirm) {
        $ans = [Windows.MessageBox]::Show("Run '$Label' on $env:COMPUTERNAME now?`n`nThis changes system state.", 'Confirm action', 'YesNo', 'Warning')
        if ($ans -ne 'Yes') { return }
    }
    Write-DxConsole "RUN  : $Label"
    Start-DxUiJob -ScriptText "Invoke-DxQuickAction -Name '$Name'" -StatusText "$Label ..." -OnComplete {
        param($r)
        $text = (@($r) -join "`r`n")
        if ([string]::IsNullOrWhiteSpace($text)) { $text = '(no output)' }
        Write-DxConsole "DONE : $text"
    }
}

# =============================================================================
#  Event handlers
# =============================================================================
$UI.btnScan.Add_Click({ Invoke-DxFullScan })
$UI.btnEvents.Add_Click({ Invoke-DxEventScan })
$UI.btnDiag.Add_Click({ Show-DxCollectorDiagnostic })
$UI.btnTheme.Add_Click({
    if ($script:DxThemeName -eq 'Dark') { Set-DxTheme -Name 'Light' } else { Set-DxTheme -Name 'Dark' }
    Write-DxConsole "Theme switched to $script:DxThemeName."
})
$UI.btnFilter.Add_Click({ Update-DxEventGrid -Filter $UI.txtFilter.Text })
$UI.txtFilter.Add_KeyDown({ if ($_.Key -eq 'Return') { Update-DxEventGrid -Filter $UI.txtFilter.Text } })
$UI.cboLog.Add_SelectionChanged({ Update-DxEventGrid -Filter $UI.txtFilter.Text })

# Selector.SelectionChanged BUBBLES, so inner TabControls and ComboBoxes re-raise
# it on the outer TabControl. Without this source check the handler recurses.
$UI.tabs.Add_SelectionChanged({
    param($eventSender, $e)
    if ($e.Source -ne $UI.tabs) { return }
    try {
        if ($UI.tabs.SelectedItem -eq $UI.tabPolicy) { Show-DxGpoGrids }
        if ($UI.tabs.SelectedItem -eq $UI.tabDash) { Update-DxDashboardCharts }
        if ($UI.tabs.SelectedItem -eq $UI.tabNet)  { Update-DxNetSummary }
    }
    catch { Write-DxCrash -Context 'tabs.SelectionChanged' -ErrorObject $_ | Out-Null }
})

$UI.btnAddLog.Add_Click({
    $all = Get-DxAvailableLogs
    $pick = $all | Out-GridView -Title 'Select additional event channels to include in the next scan' -PassThru
    if ($pick) {
        $script:ExtraLogs = @($script:ExtraLogs + $pick) | Select-Object -Unique
        Write-DxConsole "Added channel(s): $($pick -join ', '). Run a scan to include them."
    }
})

$UI.gridEvents.Add_SelectionChanged({
    $sel = $UI.gridEvents.SelectedItem
    if (-not $sel) { return }
    try {
        $kb = Resolve-DxEventGuidance -ProviderName $sel.Provider -EventId $sel.Id -Level $sel.Level -Message $sel.Message
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("TIME      : $($sel.TimeCreated)")
        [void]$sb.AppendLine("LOG       : $($sel.LogName)      RECORD: $($sel.RecordId)")
        [void]$sb.AppendLine("LEVEL     : $($sel.Level)")
        [void]$sb.AppendLine("PROVIDER  : $($sel.Provider)")
        [void]$sb.AppendLine("EVENT ID  : $($sel.Id)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("MESSAGE   : $($sel.Message)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("DIAGNOSIS : $($kb.Title)")
        [void]$sb.AppendLine("CAUSE     : $($kb.Cause)")
        [void]$sb.AppendLine('FIRST STEPS:')
        $n = 1
        foreach ($s in @($kb.Steps)) { [void]$sb.AppendLine("  $n. $s"); $n++ }
        $UI.txtEventDetail.Text = $sb.ToString()
    }
    catch { Write-DxCrash -Context 'gridEvents.SelectionChanged' -ErrorObject $_ | Out-Null }
})
$UI.gridEvents.Add_MouseDoubleClick({ Show-DxEventDetailWindow -EventRow $UI.gridEvents.SelectedItem })
$UI.btnEventDetail.Add_Click({ Show-DxEventDetailWindow -EventRow $UI.gridEvents.SelectedItem })

$UI.gridTop.Add_MouseDoubleClick({
    $sel = $UI.gridTop.SelectedItem
    if ($sel) {
        $UI.tabs.SelectedItem = $UI.tabEvents
        $UI.eventSubTabs.SelectedItem = $UI.tabResolutions
        $match = $UI.gridIssues.Items | Where-Object { $_.Provider -eq $sel.Provider -and $_.Id -eq $sel.Id } | Select-Object -First 1
        if ($match) { $UI.gridIssues.SelectedItem = $match; $UI.gridIssues.ScrollIntoView($match) }
    }
})

$UI.gridIssues.Add_SelectionChanged({
    $s = $UI.gridIssues.SelectedItem
    if (-not $s) { return }
    try {
        $UI.resTitle.Text = $s.Title
        $known = 'not in knowledge base - generic triage shown'
        if ($s.Known) { $known = 'knowledge-base match' }
        $UI.resMeta.Text = "$($s.Provider)  |  Event ID $($s.Id)  |  $($s.Count) occurrence(s)  |  $($s.LogName)  |  first $($s.FirstSeen)  |  last $($s.LastSeen)  |  $known"
        $UI.resCause.Text = $s.Cause
        $UI.resImpact.Text = $s.Impact
        $steps = @(); $n = 1
        foreach ($st in @($s.Steps)) { $steps += "$n.  $st"; $n++ }
        Set-DxItems -Grid $UI.resSteps -Items $steps -Label 'resSteps' | Out-Null
        Set-DxItems -Grid $UI.lstCommands -Items $s.Commands -Label 'lstCommands' | Out-Null
        $UI.resSample.Text = $s.SampleText
    }
    catch { Write-DxCrash -Context 'gridIssues.SelectionChanged' -ErrorObject $_ | Out-Null }
})

$UI.lstCommands.Add_MouseDoubleClick({
    if ($UI.lstCommands.SelectedItem) {
        try { [Windows.Clipboard]::SetText([string]$UI.lstCommands.SelectedItem) } catch { }
        Set-DxStatus -Text 'Command copied to clipboard.' -Done
    }
})
$UI.btnDocs.Add_Click({ $s = $UI.gridIssues.SelectedItem; if ($s -and $s.Docs) { Start-Process $s.Docs } })
$UI.btnCopyAll.Add_Click({
    $s = $UI.gridIssues.SelectedItem
    if (-not $s) { return }
    try {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("ISSUE   : $($s.Title)")
        [void]$sb.AppendLine("SOURCE  : $($s.Provider)  Event ID $($s.Id)  ($($s.Count) occurrences, last $($s.LastSeen))")
        [void]$sb.AppendLine("CAUSE   : $($s.Cause)")
        [void]$sb.AppendLine("IMPACT  : $($s.Impact)")
        [void]$sb.AppendLine('RESOLUTION:')
        $n = 1
        foreach ($st in @($s.Steps)) { [void]$sb.AppendLine("  $n. $st"); $n++ }
        [void]$sb.AppendLine('COMMANDS:')
        foreach ($c in @($s.Commands)) { [void]$sb.AppendLine("  $c") }
        [void]$sb.AppendLine("DOCS    : $($s.Docs)")
        [Windows.Clipboard]::SetText($sb.ToString())
        Set-DxStatus -Text 'Full resolution copied to clipboard.' -Done
    } catch { }
})

# ---- Network ----
$UI.btnNetScan.Add_Click({ Invoke-DxNetworkScan })
$UI.btnWf.Add_Click({ Open-DxConsole -File 'wf.msc' -Label 'Windows Defender Firewall with Advanced Security' })
$UI.btnFlushDns.Add_Click({ Invoke-DxAction -Name 'FlushDNS' -Label 'Flush DNS cache' })
$UI.btnNetAdapters.Add_Click({
    Start-DxUiJob -ScriptText 'Get-DxNetAdapters' -StatusText 'Reading network adapters...' -OnComplete {
        param($r)
        $script:Data.Adapters = @($r)
        Set-DxItems -Grid $UI.gridAdapters -Items $script:Data.Adapters -Label 'gridAdapters' | Out-Null
        Write-DxConsole "Adapters refreshed: $(@($script:Data.Adapters).Count) adapter(s)."
    }
})
$UI.btnFwFind.Add_Click({ Find-DxFwRules })
$UI.txtFwFind.Add_KeyDown({ if ($_.Key -eq 'Return') { Find-DxFwRules } })
$UI.cboFwDir.Add_SelectionChanged({ Find-DxFwRules })
$UI.cboFwAction.Add_SelectionChanged({ Find-DxFwRules })
$UI.btnDnsCacheFind.Add_Click({ Find-DxDnsCache })
$UI.txtDnsCacheFind.Add_KeyDown({ if ($_.Key -eq 'Return') { Find-DxDnsCache } })
$UI.btnDnsCacheRefresh.Add_Click({
    Start-DxUiJob -ScriptText 'Get-DxDnsState' -StatusText 'Re-reading DNS state...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Servers','Probes','Issues')
        if ($res) { $script:Data.Dns = $res; Update-DxDnsTab; Write-DxConsole 'DNS state refreshed.' }
    }
})

# ---- Ping cards ----
$UI.btnPingAdd.Add_Click({
    $t = $UI.txtPingTarget.Text
    if ([string]::IsNullOrWhiteSpace($t)) { Set-DxStatus -Text 'Enter a target host or IP first.' -Done; return }
    $c = New-DxPingCard -Target $t.Trim() -IntervalMs (Get-DxPingInterval) -AutoStart
    if ($c) { $UI.txtPingTarget.Text = ''; Update-DxNetSummary; Write-DxConsole "Ping card added for '$($c.Target)'." }
})
$UI.txtPingTarget.Add_KeyDown({ if ($_.Key -eq 'Return') { $UI.btnPingAdd.RaiseEvent((New-Object Windows.RoutedEventArgs([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
$UI.btnPingStartAll.Add_Click({ foreach ($c in @($script:PingCards)) { Start-DxPingCard -Card $c } })
$UI.btnPingStopAll.Add_Click({ foreach ($c in @($script:PingCards)) { Stop-DxPingCard -Card $c } })
$UI.btnPingClearAll.Add_Click({ foreach ($c in @($script:PingCards)) { Remove-DxPingCard -Card $c }; Update-DxNetSummary })
$UI.btnPingPreset.Add_Click({
    $iv = Get-DxPingInterval
    foreach ($t in (Get-DxPingPresets)) { New-DxPingCard -Target $t -IntervalMs $iv -AutoStart | Out-Null }
    Update-DxNetSummary
    Write-DxConsole 'Added standard ping set: gateway, DNS servers and cloud endpoints.'
})

# ---- Lookup cards ----
$UI.btnLookupAdd.Add_Click({
    $n = $UI.txtLookupName.Text
    if ([string]::IsNullOrWhiteSpace($n)) { Set-DxStatus -Text 'Enter a DNS name first.' -Done; return }
    $type = 'A'
    if ($UI.cboLookupType.SelectedItem) { $type = [string]$UI.cboLookupType.SelectedItem.Content }
    $c = New-DxLookupCard -Name $n.Trim() -Type $type -Server $UI.txtLookupServer.Text -AutoRun
    if ($c) { $UI.txtLookupName.Text = ''; Update-DxNetSummary; Write-DxConsole "Lookup card added for '$($n.Trim())' ($type)." }
})
$UI.txtLookupName.Add_KeyDown({ if ($_.Key -eq 'Return') { $UI.btnLookupAdd.RaiseEvent((New-Object Windows.RoutedEventArgs([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
$UI.btnLookupRunAll.Add_Click({ foreach ($c in @($script:LookupCards)) { Invoke-DxLookupCard -Card $c } })
$UI.btnLookupClearAll.Add_Click({ foreach ($c in @($script:LookupCards)) { Remove-DxLookupCard -Card $c }; Update-DxNetSummary })
$UI.btnLookupPreset.Add_Click({
    $srv = $UI.txtLookupServer.Text
    foreach ($n in @('login.microsoftonline.com','manage.microsoft.com','graph.microsoft.com')) {
        New-DxLookupCard -Name $n -Type 'A' -Server $srv -AutoRun | Out-Null
    }
    if ($env:USERDNSDOMAIN) { New-DxLookupCard -Name "_ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN" -Type 'SRV' -Server $srv -AutoRun | Out-Null }
    Update-DxNetSummary
    Write-DxConsole 'Added standard lookup set.'
})

# ---- Trace cards ----
$UI.btnTraceAdd.Add_Click({
    $t = $UI.txtTraceTarget.Text
    if ([string]::IsNullOrWhiteSpace($t)) { Set-DxStatus -Text 'Enter a target host or IP first.' -Done; return }
    $c = New-DxTraceCard -Target $t.Trim() -MaxHops (Get-DxTraceMaxHops) -ResolveNames ([bool]$UI.chkTraceNames.IsChecked) -AutoStart
    if ($c) { $UI.txtTraceTarget.Text = ''; Update-DxNetSummary; Write-DxConsole "Trace card added for '$($c.Target)'." }
})
$UI.txtTraceTarget.Add_KeyDown({ if ($_.Key -eq 'Return') { $UI.btnTraceAdd.RaiseEvent((New-Object Windows.RoutedEventArgs([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
$UI.btnTraceRunAll.Add_Click({ foreach ($c in @($script:TraceCards)) { Start-DxTraceCard -Card $c } })
$UI.btnTraceStopAll.Add_Click({ foreach ($c in @($script:TraceCards)) { Stop-DxTraceCard -Card $c } })
$UI.btnTraceClearAll.Add_Click({ foreach ($c in @($script:TraceCards)) { Remove-DxTraceCard -Card $c }; Update-DxNetSummary })
$UI.btnTracePreset.Add_Click({
    $hops = Get-DxTraceMaxHops
    $names = [bool]$UI.chkTraceNames.IsChecked
    $targets = New-Object System.Collections.ArrayList
    Invoke-DxSafe {
        Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
            foreach ($g in @($_.IPv4DefaultGateway.NextHop)) { if ($g) { $null = $targets.Add($g) } }
        }
    }
    $null = $targets.Add('login.microsoftonline.com')
    $null = $targets.Add('manage.microsoft.com')
    foreach ($t in (@($targets.ToArray()) | Select-Object -Unique | Select-Object -First 4)) {
        New-DxTraceCard -Target $t -MaxHops $hops -ResolveNames $names -AutoStart | Out-Null
    }
    Update-DxNetSummary
    Write-DxConsole 'Added standard trace set: gateway plus the Entra and Intune endpoints.'
})

# ---- Port cards ----
$UI.cboPortPreset.Add_SelectionChanged({
    try {
        $item = $UI.cboPortPreset.SelectedItem
        if ($item -and $item.Tag) { $UI.txtPortList.Text = [string]$item.Tag }
    } catch { }
})
$UI.btnPortAdd.Add_Click({
    $t = $UI.txtPortTarget.Text
    if ([string]::IsNullOrWhiteSpace($t)) { Set-DxStatus -Text 'Enter a target host or IP first.' -Done; return }
    $ports = $UI.txtPortList.Text
    if ([string]::IsNullOrWhiteSpace($ports)) { $ports = '443,80' }
    $c = New-DxPortCard -Target $t.Trim() -Ports $ports -AutoStart
    if ($c) { $UI.txtPortTarget.Text = ''; Update-DxNetSummary; Write-DxConsole "Port card added for '$($c.Target)' checking $ports." }
})
$UI.txtPortTarget.Add_KeyDown({ if ($_.Key -eq 'Return') { $UI.btnPortAdd.RaiseEvent((New-Object Windows.RoutedEventArgs([Windows.Controls.Primitives.ButtonBase]::ClickEvent))) } })
$UI.btnPortRunAll.Add_Click({ foreach ($c in @($script:PortCards)) { Start-DxPortCard -Card $c } })
$UI.btnPortStopAll.Add_Click({ foreach ($c in @($script:PortCards)) { Stop-DxPortCard -Card $c } })
$UI.btnPortClearAll.Add_Click({ foreach ($c in @($script:PortCards)) { Remove-DxPortCard -Card $c }; Update-DxNetSummary })
$UI.btnPortPreset.Add_Click({
    foreach ($h in @('login.microsoftonline.com','manage.microsoft.com','enrollment.manage.microsoft.com','graph.microsoft.com')) {
        New-DxPortCard -Target $h -Ports '443' -AutoStart | Out-Null
    }
    if ($env:USERDNSDOMAIN) { New-DxPortCard -Target $env:USERDNSDOMAIN -Ports '53,88,135,389,445,636' -AutoStart | Out-Null }
    Update-DxNetSummary
    Write-DxConsole 'Added cloud port set on 443, plus the DC port set when domain-joined.'
})

# ---- Certificates ----
$UI.btnCertScan.Add_Click({ Invoke-DxCertScan })
$UI.btnCertFind.Add_Click({ Show-DxCertGrid })
$UI.txtCertFind.Add_KeyDown({ if ($_.Key -eq 'Return') { Show-DxCertGrid } })
$UI.cboCertScope.Add_SelectionChanged({ Show-DxCertGrid })
$UI.btnCertlm.Add_Click({ Open-DxConsole -File 'certlm.msc' -Label 'Certificates (Computer)' })
$UI.btnCertmgr.Add_Click({ Open-DxConsole -File 'certmgr.msc' -Label 'Certificates (User)' })
$UI.btnCertPulse.Add_Click({ Invoke-DxAction -Name 'CertPulse' -Label 'Certificate auto-enrolment pulse' })
$UI.gridCerts.Add_SelectionChanged({
    $c = $UI.gridCerts.SelectedItem
    if (-not $c) { return }
    try {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.AppendLine("SUBJECT    : $($c.Subject)")
        [void]$sb.AppendLine("ISSUER     : $($c.Issuer)")
        [void]$sb.AppendLine("FRIENDLY   : $($c.FriendlyName)")
        [void]$sb.AppendLine("SCOPE      : $($c.Scope)   STORE: $($c.Store)   PURPOSE: $($c.Purpose)")
        [void]$sb.AppendLine("VALID      : $($c.NotBefore)  ->  $($c.NotAfter)   ($($c.DaysLeft) day(s) left, $($c.Status))")
        [void]$sb.AppendLine("KEY        : HasPrivateKey=$($c.HasKey)   Size=$($c.KeySize)   SigAlg=$($c.SigAlg)   SelfSigned=$($c.SelfSigned)")
        [void]$sb.AppendLine("TEMPLATE   : $($c.Template)")
        [void]$sb.AppendLine("EKU        : $($c.Eku)")
        [void]$sb.AppendLine("THUMBPRINT : $($c.Thumbprint)")
        [void]$sb.AppendLine("SERIAL     : $($c.Serial)")
        $UI.txtCertDetail.Text = $sb.ToString()
    }
    catch { Write-DxCrash -Context 'gridCerts.SelectionChanged' -ErrorObject $_ | Out-Null }
})

# ---- Intune ----
$UI.btnIntuneScan.Add_Click({
    $script = @'
$i = Get-DxIntuneState
$l = Get-DxIntuneLogFindings
[pscustomobject]@{ Intune=$i; Logs=$l }
'@
    Start-DxUiJob -ScriptText $script -StatusText 'Analysing Intune / MDM state...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Intune','Logs')
        if ($res) {
            $script:Data.Intune = $res.Intune
            $script:Data.IntuneLogs = @($res.Logs)
            Update-DxIntuneTab
            Write-DxConsole "Intune analysis complete: $(@($res.Intune.Win32Apps).Count) Win32 app(s), $(@($res.Intune.Scripts).Count) script(s), $(@($res.Intune.Remediations).Count) remediation(s)."
        }
    }
})
$UI.btnIntuneSync.Add_Click({ Invoke-DxAction -Name 'IntuneSync' -Label 'Trigger MDM sync' })
$UI.btnImeRestart.Add_Click({ Invoke-DxAction -Name 'RestartIME' -Label 'Restart IME service' -Confirm })
$UI.btnMdmDiag.Add_Click({ Invoke-DxAction -Name 'MdmDiagReport' -Label 'Collect MDM diagnostic bundle' })
$UI.btnOpenImeLogs.Add_Click({
    $p = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    if (Test-Path $p) { Start-Process explorer.exe $p } else { Write-DxConsole "IME log folder not present: $p" }
})

# ---- Group Policy ----
$UI.btnGpoScan.Add_Click({
    Start-DxUiJob -ScriptText 'Get-DxGpoState' -StatusText 'Generating RSoP and analysing Group Policy...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('AppliedGpos','Conflicts','Settings')
        if ($res) {
            $script:Data.Gpo = $res
            Update-DxGpoTab
            Show-DxGpoGrids
            Write-DxConsole "Group Policy analysis complete: $(@($res.AppliedGpos).Count) applied, $(@($res.Conflicts).Count) risk item(s)."
        }
    }
})
$UI.btnGpUpdate.Add_Click({ Invoke-DxAction -Name 'GpupdateForce' -Label 'gpupdate /force' })
$UI.btnGpHtml.Add_Click({ Invoke-DxAction -Name 'GpresultHtml' -Label 'RSoP HTML report' })
$UI.btnGpoFind.Add_Click({ Find-DxGpoSettings })
$UI.txtGpoFind.Add_KeyDown({ if ($_.Key -eq 'Return') { Find-DxGpoSettings } })

# ---- System ----
$UI.btnSysScan.Add_Click({
    Start-DxUiJob -ScriptText 'Get-DxSystemDiagnostics' -StatusText 'Running system diagnostics...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Volumes','Connectivity','ProblemDevices')
        if ($res) { $script:Data.SysDiag = $res; Update-DxSysTab; Write-DxConsole 'System diagnostics complete.' }
    }
})

# ---- Action buttons ----
$UI.actGpupdate.Add_Click({ Invoke-DxAction -Name 'GpupdateForce' -Label 'gpupdate /force' })
$UI.actGpHtml.Add_Click({ Invoke-DxAction -Name 'GpresultHtml' -Label 'RSoP HTML report' })
$UI.actDns.Add_Click({ Invoke-DxAction -Name 'FlushDNS' -Label 'Flush DNS cache' })
$UI.actRegDns.Add_Click({ Invoke-DxAction -Name 'RegisterDns' -Label 'Re-register DNS records' })
$UI.actFwLog.Add_Click({ Invoke-DxAction -Name 'FirewallLogOn' -Label 'Enable firewall drop logging' })
$UI.actRenew.Add_Click({ Invoke-DxAction -Name 'ReleaseRenew' -Label 'Release and renew DHCP lease' -Confirm })
$UI.actWinsock.Add_Click({ Invoke-DxAction -Name 'ResetWinsock' -Label 'Reset Winsock' -Confirm })
$UI.actIpReset.Add_Click({ Invoke-DxAction -Name 'ResetIpStack' -Label 'Reset TCP/IP and Winsock stack' -Confirm })
$UI.actFwReset.Add_Click({ Invoke-DxAction -Name 'FirewallReset' -Label 'Reset firewall to defaults' -Confirm })
$UI.actSync.Add_Click({ Invoke-DxAction -Name 'IntuneSync' -Label 'MDM sync' })
$UI.actCertPulse.Add_Click({ Invoke-DxAction -Name 'CertPulse' -Label 'Certificate auto-enrolment pulse' })
$UI.actIme.Add_Click({ Invoke-DxAction -Name 'RestartIME' -Label 'Restart IME service' -Confirm })
$UI.actImeCache.Add_Click({ Invoke-DxAction -Name 'ClearIMECache' -Label 'Clear IME content cache' -Confirm })
$UI.actMdmDiag.Add_Click({ Invoke-DxAction -Name 'MdmDiagReport' -Label 'MDM diagnostic bundle' })
$UI.actSfc.Add_Click({ Invoke-DxAction -Name 'SFC' -Label 'SFC /scannow' -Confirm })
$UI.actDism.Add_Click({ Invoke-DxAction -Name 'DISM' -Label 'DISM RestoreHealth' -Confirm })
$UI.actWu.Add_Click({ Invoke-DxAction -Name 'ClearWUCache' -Label 'Reset Windows Update cache' -Confirm })
$UI.actSpooler.Add_Click({ Invoke-DxAction -Name 'RestartSpooler' -Label 'Restart print spooler' -Confirm })

function Export-DxReport {
    if (-not $script:Data.Snapshot) {
        [Windows.MessageBox]::Show('Run a scan first so there is something to report on.', 'Sys@dmin', 'OK', 'Information') | Out-Null
        return
    }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'HTML report (*.html)|*.html'
    $dlg.FileName = "Sysadmin-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').html"
    $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $path = New-DxHtmlReport -Snapshot $script:Data.Snapshot -EventStats $script:Data.EventStats `
                             -EventSummary $script:Data.EventSummary -Intune $script:Data.Intune `
                             -Gpo $script:Data.Gpo -SysDiag $script:Data.SysDiag -Health $script:Data.Health `
                             -Certs $script:Data.Certs -Firewall $script:Data.Firewall -Dns $script:Data.Dns `
                             -Path $dlg.FileName
    Write-DxConsole "Report written: $path"
    Start-Process $path
}
$UI.btnExport.Add_Click({ Export-DxReport })
$UI.actHtml.Add_Click({ Export-DxReport })

$UI.actJson.Add_Click({
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'JSON (*.json)|*.json'
    $dlg.FileName = "Sysadmin-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').json"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $payload = [pscustomobject]@{
        Snapshot=$script:Data.Snapshot; EventStats=$script:Data.EventStats
        EventSummary=$script:Data.EventSummary; IntuneIssues=$script:Data.Intune.Issues
        Win32Apps=$script:Data.Intune.Win32Apps; Scripts=$script:Data.Intune.Scripts
        Remediations=$script:Data.Intune.Remediations
        GpoConflicts=$script:Data.Gpo.Conflicts; Certificates=$script:Data.Certs
        FirewallProfiles=$script:Data.Firewall.Profiles; FirewallIssues=$script:Data.Firewall.Issues
        DnsServers=$script:Data.Dns.Servers; DnsIssues=$script:Data.Dns.Issues
        Health=$script:Data.Health
    }
    $p = Export-DxJson -Data $payload -Path $dlg.FileName
    Write-DxConsole "JSON written: $p"
})

$UI.actCsv.Add_Click({
    if (@($script:Data.Events).Count -eq 0) { Write-DxConsole 'No events collected yet.'; return }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "Sysadmin-Events-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $script:Data.Events | Select-Object TimeCreated, Level, Id, Provider, LogName, RecordId, Message |
        Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    Write-DxConsole "CSV written: $($dlg.FileName)"
})

$UI.actCertCsv.Add_Click({
    if (@($script:Data.Certs).Count -eq 0) { Write-DxConsole 'No certificates collected yet.'; return }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "Sysadmin-Certs-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $script:Data.Certs | Select-Object Scope, Store, SubjectCN, IssuerCN, Purpose, NotBefore, NotAfter,
        DaysLeft, Status, HasKey, KeySize, SigAlg, Template, Eku, Thumbprint |
        Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    Write-DxConsole "Certificate CSV written: $($dlg.FileName)"
})

$UI.actFwCsv.Add_Click({
    if (-not $script:Data.Firewall -or @($script:Data.Firewall.Rules).Count -eq 0) {
        Write-DxConsole 'No firewall rules collected yet. Run the Network tab first.'
        return
    }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "Sysadmin-Firewall-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').csv"
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $script:Data.Firewall.Rules | Select-Object DisplayName, Direction, Action, Profile, Protocol,
        LocalPort, RemotePort, Program, Group, PolicyStore |
        Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    Write-DxConsole "Firewall rules CSV written: $($dlg.FileName)"
})

# ---- redraw charts on resize (responsive layout) ----
foreach ($cv in @($UI.cvProviders, $UI.cvTimeline, $UI.cvCertPurpose, $UI.cvDisks, $UI.cvFwRules, $UI.cvDnsProbe, $UI.cvSeverity, $UI.cvCertStatus)) {
    if ($cv) {
        $cv.Add_SizeChanged({
            try {
                if     ($this -eq $UI.cvProviders)   { Show-DxHBars -Canvas $this -Data (Get-DxTopProviders -Events $script:Data.Events -Top 7) }
                elseif ($this -eq $UI.cvTimeline)    { Show-DxVBars -Canvas $this -Data (Get-DxEventTimeline -Events $script:Data.Events -Buckets 12) }
                elseif ($this -eq $UI.cvSeverity)    { Show-DxDonut -Canvas $this -Data (Get-DxSeverityChartData -Stats $script:Data.EventStats) -CenterLabel 'events' }
                elseif ($this -eq $UI.cvCertPurpose) { if ($script:Data.CertSummary) { Show-DxHBars -Canvas $this -Data $script:Data.CertSummary.PurposeChart -LabelW 175 } }
                elseif ($this -eq $UI.cvCertStatus)  { if ($script:Data.CertSummary) { Show-DxDonut -Canvas $this -Data $script:Data.CertSummary.StatusChart -CenterLabel 'certs' } }
                elseif ($this -eq $UI.cvDisks)       { Show-DxHBars -Canvas $this -Data (Get-DxDiskChartData -Snapshot $script:Data.Snapshot) -LabelW 140 }
                elseif ($this -eq $UI.cvFwRules)     { if ($script:Data.Firewall) { Show-DxHBars -Canvas $this -Data $script:Data.Firewall.RuleChart -LabelW 110 } }
                elseif ($this -eq $UI.cvDnsProbe)    { if ($script:Data.Dns) { Show-DxHBars -Canvas $this -Data $script:Data.Dns.ProbeChart -LabelW 190 } }
            }
            catch { }
        })
    }
}


# =============================================================================
#  ADVANCED SYSTEM HEALTH   (hardware, posture, resource pressure)
# =============================================================================
$script:DxDriverView = 'Key'

function Get-DxKpiText {
    # A KPI card must not show 0 when the truth is "not measured" - that reads
    # as a clean result and is worse than an obvious blank.
    param($Value, [string]$Suffix = '', [string]$Empty = '--')
    if ($null -eq $Value -or "$Value" -eq '') { return $Empty }
    return "$Value$Suffix"
}

function Update-DxDriverGrid {
    $d = $null
    if ($script:Data.Adv) { $d = $script:Data.Adv.Drivers }
    if (-not $d) {
        Set-DxItems -Grid $UI.gridDrivers -Items @() -Label 'gridDrivers' | Out-Null
        $UI.lblDrvRows.Text = 'No driver data yet - run the hardware and posture checks.'
        return
    }
    $rows = @()
    switch ($script:DxDriverView) {
        'All'      { $rows = @($d.All) }
        'Key'      { $rows = @($d.KeyClasses) }
        'Stale'    { $rows = @($d.Stale) }
        'Unsigned' { $rows = @($d.Unsigned) }
        default    { $rows = @($d.KeyClasses) }
    }
    $shown = Set-DxItems -Grid $UI.gridDrivers -Items $rows -Label 'gridDrivers' -Cap 1200
    $UI.lblDrvRows.Text = "$($script:DxDriverView): showing $shown of $(@($d.All).Count) driver(s)  |  $(@($d.Unsigned).Count) unsigned, $(@($d.Stale).Count) stale"
}

function Update-DxAdvTab {
    $a = $script:Data.Adv
    if (-not $a) {
        $UI.lblAdvSummary.Text = 'Hardware and posture not checked yet.'
        return
    }
    try {
        # ---- battery ----
        if ($a.Battery) {
            Set-DxItems -Grid $UI.gridBattery -Items $a.Battery.Batteries -Label 'gridBattery' | Out-Null
            $UI.kpiBattWear.Text = Get-DxKpiText -Value $a.Battery.WorstWearPct -Suffix '%' -Empty 'n/a'
            if ($a.Battery.Note) {
                $UI.lblBattNote.Text = $a.Battery.Note
            } elseif (@($a.Battery.Batteries).Count -gt 0) {
                $UI.lblBattNote.Text = "$(@($a.Battery.Batteries)[0].Health) - $(@($a.Battery.Batteries).Count) pack(s)"
            }
        }

        # ---- storage ----
        if ($a.Storage) {
            Set-DxItems -Grid $UI.gridStorageHealth -Items $a.Storage.Disks -Label 'gridStorageHealth' | Out-Null
            $worn = @(@($a.Storage.Disks) | Where-Object { $null -ne $_.WearPct } | Sort-Object WearPct -Descending)
            if (@($worn).Count -gt 0) {
                $UI.kpiDiskWear.Text = "$($worn[0].WearPct)%"
                $UI.lblDiskNote.Text = "$($worn[0].Model)"
            } else {
                $UI.kpiDiskWear.Text = 'n/a'
                if ($a.Storage.Note) { $UI.lblDiskNote.Text = $a.Storage.Note }
                else { $UI.lblDiskNote.Text = 'no wear indicator reported' }
            }
        }

        # ---- posture ----
        if ($a.Posture) {
            Set-DxItems -Grid $UI.gridPosture -Items $a.Posture.Rows -Label 'gridPosture' | Out-Null
            Set-DxItems -Grid $UI.gridBitlocker -Items $a.Posture.BitLocker -Label 'gridBitlocker' | Out-Null

            $rowFor = {
                param([string]$Setting)
                @($a.Posture.Rows | Where-Object { $_.Setting -eq $Setting }) | Select-Object -First 1
            }
            $sb  = & $rowFor 'Secure Boot'
            $tpm = & $rowFor 'TPM ready'
            if ($sb) { $UI.kpiSecureBoot.Text = "$($sb.Value)" }
            if ($tpm) { $UI.lblTpmNote.Text = "TPM ready: $($tpm.Value)" }

            $vbs = & $rowFor 'Virtualisation-based security'
            $hvci = & $rowFor 'HVCI (memory integrity)'
            if ($vbs) { $UI.kpiVbs.Text = "$($vbs.Value)" }
            if ($hvci) { $UI.lblVbsNote.Text = "HVCI: $($hvci.Value)" }

            $bl = & $rowFor 'BitLocker (OS volume)'
            if ($bl) {
                $UI.kpiBitlocker.Text = "$($bl.Value)"
                $UI.lblBlNote.Text = "$(@($a.Posture.BitLocker).Count) volume(s)"
            }
        }

        # ---- memory ----
        if ($a.Memory) {
            Set-DxItems -Grid $UI.gridMemory -Items $a.Memory.Modules -Label 'gridMemory' | Out-Null
            Set-DxItems -Grid $UI.gridPageFiles -Items $a.Memory.PageFiles -Label 'gridPageFiles' | Out-Null
            $bits = New-Object System.Collections.ArrayList
            if ($null -ne $a.Memory.TotalGB) { $null = $bits.Add("$($a.Memory.TotalGB) GB total, $($a.Memory.FreeGB) GB free ($($a.Memory.UsedPct)% used)") }
            if ($null -ne $a.Memory.SlotsTotal) { $null = $bits.Add("$($a.Memory.SlotsUsed) of $($a.Memory.SlotsTotal) slot(s) populated") }
            else { $null = $bits.Add("$($a.Memory.SlotsUsed) module(s) detected") }
            $UI.lblMemSummary.Text = ((@($bits.ToArray())) -join '   |   ')
        }

        # ---- processes ----
        if ($a.Processes) {
            Set-DxItems -Grid $UI.gridProcMem -Items $a.Processes.ByMemory -Label 'gridProcMem' | Out-Null
            Set-DxItems -Grid $UI.gridProcCpu -Items $a.Processes.ByCpu -Label 'gridProcCpu' | Out-Null
        }

        # ---- drivers ----
        Update-DxDriverGrid

        # ---- uptime / boot ----
        if ($a.Uptime) {
            Set-DxItems -Grid $UI.gridBootPerf -Items $a.Uptime.BootPerf -Label 'gridBootPerf' | Out-Null
            Set-DxItems -Grid $UI.gridBootEvents -Items $a.Uptime.Events -Label 'gridBootEvents' -Cap 400 | Out-Null
            $UI.kpiUptimeDays.Text = Get-DxKpiText -Value $a.Uptime.UptimeDays -Suffix 'd'
            $UI.lblUncleanNote.Text = "$($a.Uptime.UncleanCount) unclean shutdown(s)"
        }

        # ---- findings ----
        $find = @($a.Findings)
        if (@($find).Count -eq 0) {
            $find = @('No hardware or posture findings. Every check that ran came back within tolerance.')
        }
        Set-DxItems -Grid $UI.gridAdvFindings -Items $find -Label 'gridAdvFindings' | Out-Null

        $summary = "$(@($a.Findings).Count) finding(s)"
        if (@($a.SectionErrors).Count -gt 0) {
            $summary = "$summary  |  $(@($a.SectionErrors).Count) collector section error(s) - see the console"
        }
        $UI.lblAdvSummary.Text = $summary
    }
    catch { Write-DxCrash -Context 'Update-DxAdvTab' -ErrorObject $_ | Out-Null }
}

function Invoke-DxAdvancedScan {
    # Win32_PnPSignedDriver is the slow part here (tens of seconds on some
    # machines), and Get-DxTopProcesses deliberately sleeps a second to sample
    # CPU. Both run in the background runspace, never on the UI thread.
    $hours = Get-DxSelectedHours
    $scriptLines = @(
        '$adv = Get-DxSystemHealthAdvanced -Hours $DxAdvHours'
        '[pscustomobject]@{ Adv=$adv }'
    )
    $body = $scriptLines -join "`r`n"
    Write-DxConsole 'Hardware and posture checks started. The driver inventory can take 30-60 seconds.'
    Start-DxUiJob -ScriptText $body -StatusText 'Reading battery, storage, posture, memory, drivers...' `
        -Arguments @{ DxAdvHours = $hours } -OnComplete {
            param($r)
            $res = Get-DxJobResult -Raw $r -Expect @('Adv')
            if (-not $res -or -not $res.Adv) { Write-DxConsole 'Hardware and posture checks returned no data.'; return }
            $script:Data.Adv = $res.Adv
            Update-DxAdvTab
            Update-DxDashboardKpis
            Update-DxPostureStrip
            foreach ($e in @($res.Adv.SectionErrors)) { Write-DxConsole "SECTION ERROR: $e" }
            foreach ($f in @($res.Adv.Findings)) { Write-DxConsole "FINDING: $f" }
            Write-DxConsole "Hardware and posture checks complete: $(@($res.Adv.Findings).Count) finding(s)."
        }
}

$UI.btnAdvScan.Add_Click({ Invoke-DxAdvancedScan })
$UI.btnDrvAll.Add_Click({      $script:DxDriverView = 'All';      Update-DxDriverGrid })
$UI.btnDrvKey.Add_Click({      $script:DxDriverView = 'Key';      Update-DxDriverGrid })
$UI.btnDrvStale.Add_Click({    $script:DxDriverView = 'Stale';    Update-DxDriverGrid })
$UI.btnDrvUnsigned.Add_Click({ $script:DxDriverView = 'Unsigned'; Update-DxDriverGrid })


# =============================================================================
#  Sidebar navigation
# =============================================================================
function Initialize-DxNavTips {
    <#
      An icon-only rail is unusable without tooltips, so every item carries its
      own label as one. Read from the header rather than a second hardcoded
      list, which would drift the moment a tab is renamed.
    #>
    foreach ($ti in @($UI.tabs.Items)) {
        try {
            $text = ''
            foreach ($c in @($ti.Header.Children)) {
                if ($c -is [Windows.Controls.TextBlock]) { $text = "$($c.Text)"; break }
            }
            if ($text) { $ti.ToolTip = $text }
        } catch { }
    }
}

function Set-DxNavCollapsed {
    param([bool]$Collapsed, [switch]$NoSave)
    try {
        $vis = 'Visible'
        if ($Collapsed) { $vis = 'Collapsed' }
        foreach ($ti in @($UI.tabs.Items)) {
            try {
                foreach ($c in @($ti.Header.Children)) {
                    if ($c -is [Windows.Controls.TextBlock]) { $c.Visibility = $vis }
                    elseif ($c -is [Windows.Shapes.Path]) {
                        # drop the label gutter so the icon centres in the rail
                        if ($Collapsed) { $c.Margin = New-Object Windows.Thickness(0) }
                        else { $c.Margin = New-Object Windows.Thickness(0,0,10,0) }
                    }
                }
            } catch { }
        }
        $script:DxNavCollapsed = $Collapsed
        if ($UI.btnNavToggle) {
            if ($Collapsed) { $UI.btnNavToggle.Content = 'Expand menu' }
            else { $UI.btnNavToggle.Content = 'Collapse menu' }
        }
        if (-not $NoSave) {
            $v = '0'; if ($Collapsed) { $v = '1' }
            try { Set-Content -Path $script:DxNavFile -Value $v -Encoding UTF8 } catch { }
        }
        # The rail column is Width="Auto", so the content area reflows on its
        # own - but the canvases inside it are drawn imperatively and do not.
        try { Redraw-DxAllCharts } catch { }
    }
    catch { Write-DxCrash -Context 'Set-DxNavCollapsed' -ErrorObject $_ | Out-Null }
}

function Initialize-DxNav {
    Initialize-DxNavTips
    $c = $false
    try {
        if (Test-Path $script:DxNavFile) {
            if ((Get-Content -Path $script:DxNavFile -Raw -ErrorAction Stop).Trim() -eq '1') { $c = $true }
        }
    } catch { }
    Set-DxNavCollapsed -Collapsed $c -NoSave
}

$UI.btnNavToggle.Add_Click({ Set-DxNavCollapsed -Collapsed (-not $script:DxNavCollapsed) })


# =============================================================================
#  DEEP INTUNE / MDM VIEWS
# =============================================================================

function Update-DxIntuneDeepTab {
    $d = $script:Data.IntuneDeep
    $i = $script:Data.Intune
    if (-not $d) {
        $UI.lblIntuneSummary.Text = 'Deep diagnostics not run yet.'
        return
    }
    try {
        # ---- management health ----
        $UI.kpiIntuneScore.Text = Get-DxKpiText -Value $d.Score
        $UI.lblIntuneVerdict.Text = "$($d.Verdict)"

        # ---- sync ----
        if ($d.Sync) {
            $s = $d.Sync
            $UI.kpiSyncAge.Text = Get-DxKpiText -Value $s.AgeHours -Suffix 'h'
            $UI.lblSyncNote.Text = "$($s.Verdict)"
            Set-DxItems -Grid $UI.gridSyncSessions -Items $s.Sessions -Label 'gridSyncSessions' -Cap 300 | Out-Null
            $bits = New-Object System.Collections.ArrayList
            $null = $bits.Add("Last confirmed session: $(Get-DxText $s.LastSuccess)")
            $null = $bits.Add("Last task attempt: $(Get-DxText $s.LastAttempt)")
            $null = $bits.Add("Verdict: $($s.Verdict)")
            if ($s.ServerAccount) { $null = $bits.Add("OMA-DM account: $($s.ServerAccount)") }
            $txt = (@($bits.ToArray()) -join '   |   ')
            if ($s.Note) { $txt = "$txt`r`n$($s.Note)" }
            $UI.lblSyncSummary.Text = $txt
        }

        # ---- endpoints ----
        if ($d.Endpoints) {
            $e = $d.Endpoints
            $tot = @($e.Results).Count
            $ok = @(@($e.Results) | Where-Object { $_.State -ne 'Fail' }).Count
            $UI.kpiEndpoints.Text = "$ok/$tot"
            if ([int]$e.FailCount -eq 0) { $UI.lblEndpointsNote.Text = 'all reachable on 443' }
            else { $UI.lblEndpointsNote.Text = "$($e.FailCount) unreachable" }
            Set-DxItems -Grid $UI.gridEndpoints -Items $e.Results -Label 'gridEndpoints' | Out-Null
            $UI.lblProxy.Text = "WinHTTP proxy (SYSTEM context): $($e.WinHttpProxy)"
        }

        # ---- certificates ----
        if ($d.Certificates) {
            Set-DxItems -Grid $UI.gridMdmCerts -Items $d.Certificates.Certificates -Label 'gridMdmCerts' | Out-Null
            $mdm = @(@($d.Certificates.Certificates) | Where-Object { $_.Role -like 'MDM management*' }) | Select-Object -First 1
            if ($mdm) {
                $UI.kpiMdmCert.Text = Get-DxKpiText -Value $mdm.DaysLeft -Suffix 'd' -Empty 'none'
                $UI.lblMdmCertNote.Text = "$($mdm.State)"
            }
        }

        # ---- autopilot ----
        if ($d.Autopilot) {
            Set-DxItems -Grid $UI.gridAutopilot -Items $d.Autopilot.Rows -Label 'gridAutopilot' | Out-Null
            Set-DxItems -Grid $UI.gridApEvents -Items $d.Autopilot.Events -Label 'gridApEvents' -Cap 200 | Out-Null
        }

        # ---- MSI / LOB apps ----
        $nMsi = 0
        if ($d.Apps) {
            $nMsi = Set-DxItems -Grid $UI.gridMsiApps -Items $d.Apps.Apps -Label 'gridMsiApps'
            if ($nMsi -eq 0) {
                $UI.lblMsiApps.Text = 'MSI AND LINE-OF-BUSINESS APPS  -  none assigned by this path'
            } else {
                $UI.lblMsiApps.Text = "MSI AND LINE-OF-BUSINESS APPS  ($nMsi)"
            }
        }

        # ---- failing counts ----
        $failW = 0; $failM = 0
        if ($i) { $failW = @(@($i.Win32Apps) | Where-Object { "$($_.State)" -like 'FAILED*' }).Count }
        if ($d.Apps) { $failM = @(@($d.Apps.Apps) | Where-Object { "$($_.Status)" -like 'FAILED*' }).Count }
        $UI.kpiAppsFailed.Text = "$($failW + $failM)"
        $UI.lblAppsNote.Text = "$failW Win32, $failM MSI/LOB"

        if ($i) {
            $bad = @(@($i.Scripts) + @($i.Remediations) | Where-Object {
                "$($_.ErrorCode)" -and "$($_.ErrorCode)" -ne '0'
            }).Count
            $UI.kpiScriptsFailed.Text = "$bad"
            $UI.lblScriptsNote.Text = "$(@($i.Scripts).Count) scripts, $(@($i.Remediations).Count) remediations"
        }

        # ---- timeline ----
        Set-DxItems -Grid $UI.gridTimeline -Items $d.Timeline -Label 'gridTimeline' -Cap 300 | Out-Null

        # ---- merge deep findings into the Findings list ----
        $all = New-Object System.Collections.ArrayList
        if ($i) { foreach ($f in @($i.Issues)) { $null = $all.Add("$f") } }
        foreach ($f in @($d.Findings)) { $null = $all.Add("$f") }
        if ($all.Count -eq 0) { $null = $all.Add('No MDM problems detected on this device.') }
        Set-DxItems -Grid $UI.lstIntuneIssues -Items @($all.ToArray()) -Label 'lstIntuneIssues' | Out-Null

        $UI.lblIntuneSummary.Text = "$($d.Verdict) - score $($d.Score)/100, $(@($d.Findings).Count) deep finding(s)"
        foreach ($e in @($d.SectionErrors)) { Write-DxConsole "SECTION ERROR: $e" }
    }
    catch { Write-DxCrash -Context 'Update-DxIntuneDeepTab' -ErrorObject $_ | Out-Null }
}

function Invoke-DxIntuneDeepScan {
    # Endpoint probes run in the background runspace - seven TCP connects with
    # a 3s ceiling each would visibly freeze the UI thread on a bad network.
    $body = @(
        '$base = Get-DxIntuneState'
        '$deep = Get-DxIntuneDeep -Intune $base'
        '[pscustomobject]@{ Intune=$base; IntuneDeep=$deep }'
    ) -join "`r`n"
    Write-DxConsole 'Deep Intune diagnostics started: sync health, endpoint reachability, certificates, Autopilot, MSI/LOB apps.'
    Start-DxUiJob -ScriptText $body -StatusText 'Probing MDM channel, endpoints and certificates...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Intune','IntuneDeep')
        if (-not $res -or -not $res.IntuneDeep) { Write-DxConsole 'Deep Intune diagnostics returned no data.'; return }
        $script:Data.Intune = $res.Intune
        $script:Data.IntuneDeep = $res.IntuneDeep
        Update-DxIntuneTab
        Update-DxIntuneDeepTab
        Update-DxPostureStrip
        foreach ($f in @($res.IntuneDeep.Findings)) { Write-DxConsole "FINDING: $f" }
        Write-DxConsole "Deep Intune diagnostics complete: $($res.IntuneDeep.Verdict), score $($res.IntuneDeep.Score)/100."
    }
}

function Invoke-DxEndpointTest {
    $body = @(
        '$e = Test-DxIntuneEndpoints'
        '[pscustomobject]@{ Endpoints=$e }'
    ) -join "`r`n"
    Write-DxConsole 'Testing Intune and Entra service endpoints on TCP 443 from SYSTEM context.'
    Start-DxUiJob -ScriptText $body -StatusText 'Testing service endpoints...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Endpoints')
        if (-not $res -or -not $res.Endpoints) { Write-DxConsole 'Endpoint test returned no data.'; return }
        $e = $res.Endpoints
        Set-DxItems -Grid $UI.gridEndpoints -Items $e.Results -Label 'gridEndpoints' | Out-Null
        $tot = @($e.Results).Count
        $ok = @(@($e.Results) | Where-Object { $_.State -ne 'Fail' }).Count
        $UI.kpiEndpoints.Text = "$ok/$tot"
        if ([int]$e.FailCount -eq 0) { $UI.lblEndpointsNote.Text = 'all reachable on 443' }
        else { $UI.lblEndpointsNote.Text = "$($e.FailCount) unreachable" }
        $UI.lblProxy.Text = "WinHTTP proxy (SYSTEM context): $($e.WinHttpProxy)"
        foreach ($f in @($e.Findings)) { Write-DxConsole "FINDING: $f" }
        Write-DxConsole "Endpoint test complete: $ok of $tot reachable."
    }
}

$UI.btnIntuneDeep.Add_Click({ Invoke-DxIntuneDeepScan })
$UI.btnEndpointTest.Add_Click({ Invoke-DxEndpointTest })

$window.Add_Closing({
    foreach ($set in @($script:PingCards, $script:LookupCards, $script:TraceCards, $script:PortCards)) {
        foreach ($c in @($set)) {
            try { if ($c.Timer) { $c.Timer.Stop() }; $c.PS.Dispose(); $c.RS.Close(); $c.RS.Dispose() } catch { }
        }
    }
    foreach ($j in @($script:Jobs)) {
        try { $j.Timer.Stop(); $j.PS.Dispose(); $j.RS.Close(); $j.RS.Dispose() } catch { }
    }
})

# =============================================================================
#  Start
# =============================================================================
$window.Add_ContentRendered({
    Initialize-DxMscBar
    Initialize-DxTheme
    Initialize-DxNav
    foreach ($t in @(Test-DxThemeTokens)) { Write-DxConsole "THEME: $t" }
    Set-DxAppIcon -FileName 'Designer.ico'
    Set-DxWindowTitle -Serial (Get-DxQuickSerial)
    Write-DxConsole "Sys@dmin v4 started on $env:COMPUTERNAME. Elevated: $script:IsElevated"
    Write-DxConsole 'Tip: drag the splitter bars between cards to resize them. Layout adapts to the window.'
    if (-not $script:IsElevated) {
        Write-DxConsole 'WARNING: not elevated. Security log, LocalMachine certificates, firewall rules and repair actions will be unavailable.'
    }
    if (-not $SkipAutoScan) { Invoke-DxFullScan }
})


# =============================================================================
#  POLICY TAB   [Part 11]
# =============================================================================
#  Built for cloud-managed devices, where gpresult shows almost nothing and
#  Policy CSP carries the real configuration.
# =============================================================================

function Get-DxPolicyDisplayArea {
    # ADMX-ingested namespaces arrive raw, e.g.
    #   microsoft_edge~Policy~microsoft_edge~Startup
    # Render that as "Edge - Startup".
    param([string]$Area, [string]$AreaName)
    $s = $AreaName
    if (-not $s) { $s = $Area }
    if (-not $s) { return '' }
    if ($s -notmatch '~') { return $s }

    $parts = New-Object System.Collections.ArrayList
    foreach ($p in ($s -split '~')) {
        $t = "$p".Trim()
        if (-not $t) { continue }
        if ($t -eq 'Policy') { continue }
        $t = $t -replace '_', ' '
        if ($t -match '^(?i)microsoft edge$') { $t = 'Edge' }
        if ($t -match '^(?i)microsoft ') { $t = $t.Substring(10) }
        $exists = $false
        foreach ($q in $parts) { if ("$q".ToLower() -eq $t.ToLower()) { $exists = $true; break } }
        if (-not $exists) { $null = $parts.Add($t) }
    }
    if ($parts.Count -eq 0) { return $s }
    return ((@($parts.ToArray())) -join ' - ')
}

function Test-DxPolicyAdmxRow {
    # *_ADMXInstanceData rows are ingestion pointers, not real settings.
    param($Row)
    $n = "$($Row.Setting)"
    if ($n -like '*_ADMXInstanceData') { return $true }
    if ("$($Row.Value)" -like 'Software\Microsoft\PolicyManager\provi*') { return $true }
    return $false
}

function Update-DxPolicyTab {
    $p = $script:Data.Policy
    if (-not $p) {
        Set-DxItems -Grid $UI.lstPolicyFindings -Items @('No policy data yet. Click "Analyse policy".') -Label 'lstPolicyFindings' | Out-Null
        return
    }
    try {
        $UI.kpiPolMdm.Text   = $p.Counts.Mdm
        $UI.kpiPolAreas.Text = $p.Counts.Areas
        $UI.kpiPolGpo.Text   = $p.Counts.Gpo
        $UI.kpiPolReg.Text   = $p.Counts.Legacy

        if ($p.MdmWinsOverGP) {
            $UI.kpiPolWins.Text = 'Intune'
            $UI.lblPolWinsNote.Text = 'MDMWinsOverGP enabled'
        } else {
            $UI.kpiPolWins.Text = 'Group Policy'
            $UI.lblPolWinsNote.Text = 'MDMWinsOverGP not set'
        }
        if ([int]$p.Counts.Gpo -eq 0) {
            $UI.lblPolGpoNote.Text = 'none - normal on cloud-only'
        } else {
            $UI.lblPolGpoNote.Text = 'from RSoP'
        }

        # area list with readable names
        $areas = New-Object System.Collections.ArrayList
        foreach ($a in @($p.Areas)) {
            $null = $areas.Add([pscustomobject]@{
                Area    = (Get-DxPolicyDisplayArea -Area $a.RawArea -AreaName $a.Area)
                RawArea = "$($a.RawArea)"
                Count   = $a.Count
            })
        }
        Set-DxItems -Grid $UI.gridPolicyAreas -Items @($areas.ToArray()) -Label 'gridPolicyAreas' | Out-Null

        Set-DxItems -Grid $UI.gridPolicyGpo -Items $p.Gpo -Label 'gridPolicyGpo' -Cap 900 | Out-Null
        $UI.lblPolicyGpoRows.Text = "GROUP POLICY SETTINGS  ($($p.Counts.Gpo))"

        Set-DxItems -Grid $UI.gridPolicyConflicts -Items $p.Conflicts -Label 'gridPolicyConflicts' | Out-Null

        $find = @($p.Issues)
        if (@($find).Count -eq 0) { $find = @('No policy findings.') }
        Set-DxItems -Grid $UI.lstPolicyFindings -Items $find -Label 'lstPolicyFindings' | Out-Null

        Find-DxPolicySettings
        $UI.lblPolicySummary.Text = "$($p.Counts.Mdm) CSP  |  $($p.Counts.Areas) areas  |  $($p.Counts.Gpo) GPO  |  $($p.Counts.Legacy) registry"
    }
    catch { Write-DxCrash -Context 'Update-DxPolicyTab' -ErrorObject $_ | Out-Null }
}

function Find-DxPolicySettings {
    $p = $script:Data.Policy
    if (-not $p) { return }
    try {
        $q = $UI.txtPolicyFind.Text
        $showAdmx = [bool]$UI.chkPolicyAdmx.IsChecked
        $areaSel = ''
        $sel = $UI.gridPolicyAreas.SelectedItem
        if ($sel) { $areaSel = "$($sel.RawArea)" }

        # ---- Policy CSP ----
        $mdm = New-Object System.Collections.ArrayList
        foreach ($r in @($p.Mdm)) {
            if (-not $showAdmx) {
                if (Test-DxPolicyAdmxRow -Row $r) { continue }
            }
            if ($areaSel -and "$($r.Area)" -ne $areaSel) { continue }
            $null = $mdm.Add([pscustomobject]@{
                Scope    = "$($r.Scope)"
                AreaName = (Get-DxPolicyDisplayArea -Area $r.Area -AreaName $r.AreaName)
                Setting  = "$($r.Setting)"
                Value    = "$($r.Value)"
                Owner    = "$($r.Owner)"
                KeyPath  = "$($r.KeyPath)"
            })
        }
        $rows = @($mdm.ToArray())
        if ($q) {
            $rx = [regex]::Escape($q)
            $rows = @($rows | Where-Object {
                $_.Setting -match $rx -or $_.Value -match $rx -or
                $_.AreaName -match $rx -or $_.Owner -match $rx -or $_.KeyPath -match $rx })
        }
        $shown = Set-DxItems -Grid $UI.gridPolicyMdm -Items $rows -Label 'gridPolicyMdm' -Cap 1500

        $bits = New-Object System.Collections.ArrayList
        $null = $bits.Add("POLICY CSP - showing $shown of $($p.Counts.Mdm)")
        if ($areaSel) { $null = $bits.Add("area: $(Get-DxPolicyDisplayArea -Area $areaSel -AreaName $areaSel)") }
        if ($q) { $null = $bits.Add("search: $q") }
        if (-not $showAdmx) { $null = $bits.Add('ADMX metadata hidden') }
        $UI.lblPolicyRows.Text = ((@($bits.ToArray())) -join '   |   ')

        # ---- registry policy ----
        $reg = @($p.Legacy)
        if ($q) {
            $rx = [regex]::Escape($q)
            $reg = @($reg | Where-Object {
                $_.Setting -match $rx -or $_.Value -match $rx -or
                $_.Area -match $rx -or $_.KeyPath -match $rx })
        }
        $rShown = Set-DxItems -Grid $UI.gridPolicyReg -Items $reg -Label 'gridPolicyReg' -Cap 1500
        $UI.lblPolicyRegRows.Text = "REGISTRY POLICY - showing $rShown of $($p.Counts.Legacy)"
    }
    catch { Write-DxCrash -Context 'Find-DxPolicySettings' -ErrorObject $_ | Out-Null }
}

function Invoke-DxPolicyScan {
    # NOTE: deliberately NOT a here-string. A nested @'...'@ inside this
    # installer's own here-string would terminate the outer one at the first
    # line that is exactly '@ - breaking the whole file.
    $scriptLines = @(
        '$gpo = Get-DxGpoState'
        '$pol = Get-DxPolicyState -Gpo $gpo'
        '[pscustomobject]@{ Policy=$pol; Gpo=$gpo }'
    )
    $body = $scriptLines -join "`r`n"
    Start-DxUiJob -ScriptText $body -StatusText 'Analysing effective policy (Policy CSP, Group Policy, registry)...' -OnComplete {
        param($r)
        $res = Get-DxJobResult -Raw $r -Expect @('Policy','Gpo')
        if (-not $res) { Write-DxConsole 'Policy scan returned no data.'; return }
        $script:Data.Policy = $res.Policy
        if ($res.Gpo) { $script:Data.Gpo = $res.Gpo }
        Update-DxPolicyTab
        Write-DxConsole "Policy scan complete: $($res.Policy.Counts.Mdm) Policy CSP setting(s) across $($res.Policy.Counts.Areas) area(s), $($res.Policy.Counts.Gpo) GPO setting(s), $($res.Policy.Counts.Legacy) registry policy value(s)."
        if (-not $res.Policy.MdmWinsOverGP -and [int]$res.Policy.Counts.Gpo -gt 0) {
            Write-DxConsole 'NOTE: MDMWinsOverGP is not set - Group Policy overrides Intune where both configure the same setting.'
        }
    }
}

$UI.btnPolicyScan.Add_Click({ Invoke-DxPolicyScan })
$UI.btnPolicyFind.Add_Click({ Find-DxPolicySettings })
$UI.txtPolicyFind.Add_KeyDown({ if ($_.Key -eq 'Return') { Find-DxPolicySettings } })
$UI.chkPolicyAdmx.Add_Click({ Find-DxPolicySettings })
$UI.gridPolicyAreas.Add_SelectionChanged({ Find-DxPolicySettings })
$UI.btnPolicyAllAreas.Add_Click({
    $UI.gridPolicyAreas.SelectedItem = $null
    Find-DxPolicySettings
})
$UI.btnPolicyClear.Add_Click({
    $UI.txtPolicyFind.Text = ''
    $UI.gridPolicyAreas.SelectedItem = $null
    Find-DxPolicySettings
})
$UI.btnPolicyCsv.Add_Click({
    $p = $script:Data.Policy
    if (-not $p) { Write-DxConsole 'Run the policy scan first.'; return }
    $dlg = New-Object Windows.Forms.SaveFileDialog
    $dlg.Filter = 'CSV (*.csv)|*.csv'
    $dlg.FileName = "Sysadmin-Policy-$env:COMPUTERNAME-$(Get-Date -f 'yyyyMMdd-HHmm').csv"
    $dlg.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')
    if ($dlg.ShowDialog() -ne 'OK') { return }
    $all = New-Object System.Collections.ArrayList
    foreach ($r in @($p.Mdm)) {
        $null = $all.Add([pscustomobject]@{
            Source='Policy CSP'; Scope="$($r.Scope)"
            Area=(Get-DxPolicyDisplayArea -Area $r.Area -AreaName $r.AreaName)
            Setting="$($r.Setting)"; Value="$($r.Value)"; SetBy="$($r.Owner)"; KeyPath="$($r.KeyPath)"
        })
    }
    foreach ($r in @($p.Legacy)) {
        $null = $all.Add([pscustomobject]@{
            Source='Registry policy'; Scope="$($r.Scope)"; Area="$($r.Area)"
            Setting="$($r.Setting)"; Value="$($r.Value)"; SetBy=''; KeyPath="$($r.KeyPath)"
        })
    }
    @($all.ToArray()) | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    Write-DxConsole "Policy CSV written: $($dlg.FileName)  ($($all.Count) row(s))"
})


# =============================================================================
#  SYSTEM TRAY  /  RUN IN BACKGROUND   [Part 13]
# =============================================================================
#  Minimise hides the window and keeps the app running; a tray icon restores
#  it. See the installer header for the design rationale.
# =============================================================================

$script:DxTray       = $null
$script:DxTrayHinted = $false

function Get-DxTrayIcon {
    # A NotifyIcon needs a System.Drawing.Icon, not a WPF BitmapImage.
    $ico = $null
    try {
        $p = Join-Path $script:AppRoot 'Designer.ico'
        if (Test-Path $p) { $ico = New-Object System.Drawing.Icon($p) }
    } catch { }
    if (-not $ico) {
        try {
            $exe = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
            $ico = [System.Drawing.Icon]::ExtractAssociatedIcon($exe)
        } catch { }
    }
    if (-not $ico) { $ico = [System.Drawing.SystemIcons]::Application }
    return $ico
}

function Show-DxWindowFromTray {
    try {
        $window.Show()
        $window.WindowState  = [Windows.WindowState]::Normal
        $window.ShowInTaskbar = $true
        $null = $window.Activate()
        # nudge to the foreground without staying pinned there
        $window.Topmost = $true
        $window.Topmost = $false
    } catch { Write-DxCrash -Context 'Show-DxWindowFromTray' -ErrorObject $_ | Out-Null }
}

function Hide-DxWindowToTray {
    try {
        $window.Hide()
        $window.ShowInTaskbar = $false
        if ($script:DxTray -and -not $script:DxTrayHinted) {
            $script:DxTrayHinted = $true
            try {
                $script:DxTray.ShowBalloonTip(3000, 'Sys@dmin',
                    'Still running in the background. Double-click the tray icon to reopen.',
                    [System.Windows.Forms.ToolTipIcon]::Info)
            } catch { }
        }
        Write-DxConsole 'Minimised to the system tray - the app is still running.'
    } catch { Write-DxCrash -Context 'Hide-DxWindowToTray' -ErrorObject $_ | Out-Null }
}

function New-DxTrayItem {
    param([string]$Text, [scriptblock]$OnClick)
    $item = New-Object System.Windows.Forms.ToolStripMenuItem
    $item.Text = $Text
    $item.add_Click($OnClick)
    return $item
}

function Initialize-DxTray {
    try {
        $ni = New-Object System.Windows.Forms.NotifyIcon
        $ni.Icon    = Get-DxTrayIcon
        $ni.Text    = 'Sys@dmin - Endpoint Diagnostics'   # tooltip cap is 63 chars
        $ni.Visible = $true

        $menu = New-Object System.Windows.Forms.ContextMenuStrip
        $open = New-DxTrayItem 'Open Sys@dmin' { Show-DxWindowFromTray }
        $open.Font = New-Object System.Drawing.Font($open.Font, [System.Drawing.FontStyle]::Bold)
        $null = $menu.Items.Add($open)
        $null = $menu.Items.Add((New-DxTrayItem 'Run full scan' { Show-DxWindowFromTray; Invoke-DxFullScan }))
        $null = $menu.Items.Add((New-DxTrayItem 'Refresh events' { Show-DxWindowFromTray; Invoke-DxEventScan }))
        $null = $menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
        $null = $menu.Items.Add((New-DxTrayItem 'Exit' {
            $script:DxTrayExit = $true
            try { if ($script:DxTray) { $script:DxTray.Visible = $false; $script:DxTray.Dispose() } } catch { }
            $script:DxTray = $null
            $window.Close()
        }))
        $ni.ContextMenuStrip = $menu

        $ni.add_MouseDoubleClick({ Show-DxWindowFromTray })
        $script:DxTray = $ni

        # minimise button -> tray. Deliberately NOT the Close event, so the
        # existing $window.Add_Closing cleanup is never fought or duplicated.
        $window.Add_StateChanged({
            if ($window.WindowState -eq [Windows.WindowState]::Minimized) { Hide-DxWindowToTray }
        })

        # tidy the icon on real exit, or a ghost lingers until you hover it
        $window.Add_Closing({
            try { if ($script:DxTray) { $script:DxTray.Visible = $false; $script:DxTray.Dispose(); $script:DxTray = $null } } catch { }
        })

        Write-DxConsole 'System tray ready - use the minimise button to run in the background.'
    }
    catch {
        Write-DxCrash -Context 'Initialize-DxTray' -ErrorObject $_ | Out-Null
        Write-DxConsole "Could not start the system tray icon: $($_.Exception.Message)"
    }
}

Initialize-DxTray

# Part 14: run MODELESS so Hide() (minimise to tray) does not end the app.
# ShowDialog() is a modal loop - Hide() on a modal window returns from it
# and exits the process. Show() + Dispatcher.Run() keeps the STA thread
# alive; the tray icon restores the window; Add_Closed ends the loop on exit.
$window.Add_Closed({ try { [System.Windows.Threading.Dispatcher]::CurrentDispatcher.InvokeShutdown() } catch {} })
$window.Show()
[System.Windows.Threading.Dispatcher]::Run()
