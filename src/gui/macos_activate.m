#import <Cocoa/Cocoa.h>

/* NAppGUI initially orders a macOS window front without making it key. */
void picker_macos_activate(void *native_window)
{
    NSWindow *window = (NSWindow *)native_window;

    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [NSApp activateIgnoringOtherApps:YES];
    [window makeKeyAndOrderFront:nil];
}
