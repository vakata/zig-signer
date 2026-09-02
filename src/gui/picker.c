/*
 * Native certificate/PIN picker for zig-signer.
 *
 * This is deliberately a separate process: NAppGUI (like Cocoa, Win32 and
 * GTK themselves) must own the main thread and its event loop. The signer
 * server invokes this helper synchronously from pick().
 */

#include "nappgui.h"
#include "osmain.h"

#include <stdio.h>
#include <string.h>

typedef struct _app_t App;

struct _app_t
{
    Window *window;
    PopUp *certificates;
    Edit *pin;
    Cell *pin_cell;
    Button *sign;
};

#if defined(__MACOS__)
extern void picker_macos_activate(void *native_window);
#endif

static int i_argc = 0;
static char **i_argv = NULL;
static bool_t i_accepted = FALSE;
static uint32_t i_selected = 0;
static char i_pin[9] = {0};

/*---------------------------------------------------------------------------*/

static void i_write_result(void);

/*---------------------------------------------------------------------------*/

static void i_finish(App *app, const bool_t accepted)
{
    if (accepted == TRUE)
    {
        const char_t *pin = edit_get_text(app->pin);
        const size_t len = strlen(pin);

        /* Keep the existing signer contract: PINs are at most eight bytes. */
        if (len == 0)
            return;

        i_selected = popup_get_selected(app->certificates);
        memcpy(i_pin, pin, len < 8 ? len : 8);
        i_pin[len < 8 ? len : 8] = '\0';
        i_accepted = TRUE;
        /* Cocoa's application loop terminates the process and never returns
         * to main(), so the IPC result must be flushed before osapp_finish(). */
        i_write_result();
    }

    osapp_finish();
}

/*---------------------------------------------------------------------------*/

static void i_OnSign(App *app, Event *event)
{
    unref(event);
    i_finish(app, TRUE);
}

/*---------------------------------------------------------------------------*/

static void i_OnCancel(App *app, Event *event)
{
    unref(event);
    i_finish(app, FALSE);
}

/*---------------------------------------------------------------------------*/

static void i_OnClose(App *app, Event *event)
{
    unref(event);
    i_finish(app, FALSE);
}

/*---------------------------------------------------------------------------*/

static void i_OnPinFilter(App *app, Event *event)
{
    const EvText *params = event_params(event, EvText);
    const size_t len = strlen(params->text);

    if (len > 8)
    {
        EvTextFilter *result = event_result(event, EvTextFilter);
        memcpy(result->text, params->text, 8);
        result->text[8] = '\0';
        result->cpos = 8;
        result->apply = TRUE;
    }

    unref(app);
}

/*---------------------------------------------------------------------------*/

static Panel *i_panel(App *app)
{
    Panel *panel = panel_create();
    Layout *layout = layout_create(2, 3);
    Layout *buttons = layout_create(2, 1);
    Label *certificate_label = label_create();
    Label *pin_label = label_create();
    Button *cancel = button_push();
    int index = 0;

    app->certificates = popup_create();
    app->pin = edit_create();

    label_text(certificate_label, "Certificate");
    label_text(pin_label, "PIN");
    edit_passmode(app->pin, TRUE);
    edit_autoselect(app->pin, TRUE);
    edit_tooltip(app->pin, "Enter the certificate PIN (up to 8 characters)");
    edit_OnFilter(app->pin, listener(app, i_OnPinFilter, App));

    for (index = 1; index < i_argc; ++index)
        popup_add_elem(app->certificates, i_argv[index], NULL);

    button_text(cancel, "Cancel");
    app->sign = button_push();
    button_text(app->sign, "Sign");
    button_OnClick(cancel, listener(app, i_OnCancel, App));
    button_OnClick(app->sign, listener(app, i_OnSign, App));

    layout_button(buttons, cancel, 0, 0);
    layout_button(buttons, app->sign, 1, 0);
    layout_hmargin(buttons, 0, 8);

    layout_label(layout, certificate_label, 0, 0);
    layout_popup(layout, app->certificates, 1, 0);
    layout_label(layout, pin_label, 0, 1);
    layout_edit(layout, app->pin, 1, 1);
    app->pin_cell = layout_cell(layout, 1, 1);
    layout_layout(layout, buttons, 1, 2);
    layout_hsize(layout, 1, 360);
    layout_hmargin(layout, 0, 12);
    layout_vmargin(layout, 0, 12);
    layout_vmargin(layout, 1, 16);
    layout_halign(layout, 1, 2, ekRIGHT);
    layout_margin(layout, 20);

    panel_layout(panel, layout);
    return panel;
}

/*---------------------------------------------------------------------------*/

static App *i_create(void)
{
    App *app = heap_new0(App);
    Panel *panel = NULL;
    S2Df screen;
    S2Df size;

    app->window = window_create(ekWINDOW_TITLE | ekWINDOW_CLOSE | ekWINDOW_RETURN | ekWINDOW_ESC);
    panel = i_panel(app);
    window_panel(app->window, panel);
    window_defbutton(app->window, app->sign);
    window_title(app->window, "Zig Signer");
    window_OnClose(app->window, listener(app, i_OnClose, App));

    screen = gui_resolution();
    size = window_get_size(app->window);
    window_origin(app->window, v2df((screen.width - size.width) / 2.f, (screen.height - size.height) / 2.f));
    window_show(app->window);
#if defined(__MACOS__)
    picker_macos_activate(window_imp(app->window));
#endif
    cell_focus(app->pin_cell);
    return app;
}

/*---------------------------------------------------------------------------*/

static void i_destroy(App **app)
{
    window_destroy(&(*app)->window);
    heap_delete(app, App);
}

/*---------------------------------------------------------------------------*/

static void i_write_result(void)
{
    size_t index = 0;

    if (i_accepted == FALSE)
        return;

    /* Hex keeps arbitrary PIN bytes out of the line-oriented protocol. */
    printf("ZIG_SIGNER_RESULT %u ", i_selected);
    while (i_pin[index] != '\0' && index < 8)
    {
        printf("%02x", (unsigned char)i_pin[index]);
        ++index;
    }
    printf("\n");
    fflush(stdout);
    memset(i_pin, 0, sizeof(i_pin));
}

/*---------------------------------------------------------------------------*/

#if defined(__WINDOWS__)

#include <Windows.h>

extern int __argc;
extern char **__argv;

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command_line, int show)
{
    unref(previous);
    unref(command_line);
    unref(show);
    i_argc = __argc;
    i_argv = __argv;
    osmain_imp(0, NULL, (void *)instance, 0., (FPtr_app_create)i_create, NULL, (FPtr_destroy)i_destroy, "");
    return i_accepted == TRUE ? 0 : 2;
}

#else

int main(int argc, char **argv)
{
    i_argc = argc;
    i_argv = argv;
    osmain_imp((uint32_t)argc, (char_t **)argv, NULL, 0., (FPtr_app_create)i_create, NULL, (FPtr_destroy)i_destroy, "");
    return i_accepted == TRUE ? 0 : 2;
}

#endif
