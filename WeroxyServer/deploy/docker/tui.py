"""Responsive terminal manager; all navigation and results stay in curses."""
import argparse
import contextlib
import curses
import io
import subprocess
import threading
import unicodedata

import console

ACTIONS = [action for action in console.ACTIONS if action != 'notices'] + ['quit']
LABELS = ['Install', 'Start', 'Stop', 'Restart', 'Status', 'Reset password', 'Uninstall', 'Update', 'Exit']
DESCRIPTIONS = [
    'Verify the release, prepare data and start the container. Create the account in Web.',
    'Check the release and ports, then start the existing deployment.',
    'Stop the container and pause this deployment\'s background tasks. Keep data.',
    'Stop and start the existing deployment. Connections will reconnect.',
    'Show the container, Web address and available ports.',
    'Set a new administrator password. Account name stays unchanged.',
    'Remove this deployment\'s containers and tasks. Keep its database and backups.',
    'Check GitHub releases and install a verified update with rollback.',
    'Close the manager. Running services remain running.',
]


def clip(value, width):
    out = ''; used = 0
    for char in str(value):
        if unicodedata.category(char).startswith('C'):
            continue
        size = 2 if unicodedata.east_asian_width(char) in ('W', 'F') else 1
        if used + size > width:
            break
        out += char; used += size
    return out


def wrap(value, width):
    """Wrap by terminal cells, including CJK operation messages."""
    width = max(2, width)
    lines = []
    for source in str(value).splitlines() or ['']:
        clean = ''.join(c for c in source if not unicodedata.category(c).startswith('C'))
        if not clean:
            lines.append('')
        while clean:
            line = clip(clean, width)
            lines.append(line)
            clean = clean[len(line):]
    return lines


def put(screen, row, col, value, attr=0):
    height, width = screen.getmaxyx()
    if 0 <= row < height and 0 <= col < width - 1:
        with contextlib.suppress(curses.error):
            screen.addstr(row, col, clip(value, width-col-1), attr)


def color(number):
    with contextlib.suppress(curses.error):
        if curses.has_colors():
            return curses.color_pair(number)
    return 0


def available(action, state):
    if action in ('quit', 'status', 'notices'):
        return True
    return not state['installed'] if action == 'install' else state['installed']


def read_key(screen, timeout=-1, wide=False):
    """Accept both normal CSI and application-mode terminal cursor keys."""
    read = screen.get_wch if wide else screen.getch
    key = read()
    if key not in (27, '\x1b'):
        return key
    screen.timeout(25)
    try:
        try:
            first = read()
        except curses.error:
            return 27
        if first in (-1, ''):
            return 27
        first = chr(first) if isinstance(first, int) else first
        if first not in ('[', 'O'):
            with contextlib.suppress(curses.error):
                curses.unget_wch(first)
            return 27
        sequence = first
        for _ in range(5):
            try:
                char = read()
            except curses.error:
                return 27
            if char == -1:
                return 27
            char = chr(char) if isinstance(char, int) else char
            sequence += char
            if char.isalpha() or char == '~':
                break
        return {'[A':curses.KEY_UP, 'OA':curses.KEY_UP,
                '[B':curses.KEY_DOWN, 'OB':curses.KEY_DOWN,
                '[H':curses.KEY_HOME, 'OH':curses.KEY_HOME, '[1~':curses.KEY_HOME,
                '[F':curses.KEY_END, 'OF':curses.KEY_END, '[4~':curses.KEY_END,
                '[5~':curses.KEY_PPAGE, '[6~':curses.KEY_NPAGE}.get(sequence, 27)
    finally:
        screen.timeout(timeout)


def dialog(screen, title, prompt='', secret=False):
    value = ''
    with contextlib.suppress(curses.error):
        curses.curs_set(1)
    try:
        while True:
            screen.erase(); height, width = screen.getmaxyx()
            if height < 8 or width < 30:
                put(screen, 0, 0, 'Resize terminal; Esc: back')
            else:
                put(screen, 1, 2, title, curses.A_BOLD | color(1))
                for row, line in enumerate(wrap(prompt, width-4)[:2], 3):
                    put(screen, row, 2, line)
                shown = '*' * len(value) if secret else value
                # Keep the end of a long input visible next to its cursor.
                while len(shown) and len(clip(shown, width-7)) < len(shown):
                    shown = shown[1:]
                put(screen, height-4, 2, '> ' + shown)
                put(screen, height-2, 2, 'Enter: submit   Esc: back   Ctrl-U: clear', curses.A_DIM)
                with contextlib.suppress(curses.error):
                    screen.move(height-4, min(width-2, 4+sum(2 if unicodedata.east_asian_width(c) in ('W','F') else 1 for c in shown)))
            screen.refresh()
            try:
                key = read_key(screen, wide=True)
            except curses.error:
                continue
            if key in (27, '\x1b', '\x03'):
                return None
            if key in ('\n', '\r', curses.KEY_ENTER) and height >= 8 and width >= 30:
                return value if secret else value.strip()
            if key == curses.KEY_RESIZE:
                continue
            if key == '\x15':
                value = ''
            elif key in (curses.KEY_BACKSPACE, '\x7f', '\b'):
                value = value[:-1]
            elif isinstance(key, str) and key.isprintable() and len(value) < 1024:
                value += key
    finally:
        with contextlib.suppress(curses.error):
            curses.curs_set(0)


def parameters(screen, action, lang='en'):
    args = argparse.Namespace(username=None, password=None, lang='en')
    if action == 'update':
        args.update_cancel = threading.Event()
        args.update_installing = threading.Event()
        import update
        release = update.check()
        current = console.summary()['version']
        if update.version(release['tag_name']) <= update.version(current):
            args.update_release = release
            return args
        answer = dialog(screen, 'Update ' + current + ' to ' + release['tag_name'],
                        'Connections will restart. Type UPDATE to continue. ' + release['html_url'])
        if answer != 'UPDATE':
            return None
        args.update_release = release
        args.update_confirmed = True
    if action == 'reset-password':
        args.username = dialog(screen, 'Reset password / 1 of 2', 'Administrator username')
        if not args.username:
            return None
        args.password = dialog(screen, 'Reset password / 2 of 2', 'New password (at least 6 bytes)', secret=True)
        if args.password is None:
            return None
    return args


def result(screen, title, body, running=False, offset=0, outcome=''):
    screen.erase(); height, width = screen.getmaxyx()
    lines = wrap(body, width-4)
    count = max(1, height-5)
    offset = max(0, min(offset, max(0, len(lines)-count)))
    status = 'Working' if running else outcome
    attr = color(3 if outcome == 'Failed' else 2 if outcome == 'Completed' else 1)
    put(screen, 0, 2, title + (' / ' + status if status else ''), curses.A_BOLD | attr)
    for row, line in enumerate(lines[offset:offset+count], 2):
        put(screen, row, 2, line)
    put(screen, height-2, 2, str(offset+1) + '-' + str(min(offset+count,len(lines))) + ' / ' + str(len(lines)) + ' lines', curses.A_DIM)
    footer = 'Working; please wait.  Up/Down: scroll' if running else 'Enter / Esc / q: back   Up/Down/PgUp/PgDn: scroll'
    put(screen, height-1, 1, footer)
    screen.refresh()
    return offset


class OperationOutput(io.StringIO):
    LIMIT = 256 * 1024

    def __init__(self):
        super().__init__(); self.lock = threading.Lock()

    def write(self, value):
        with self.lock:
            super().write(value)
            if self.tell() > self.LIMIT:
                tail = super().getvalue()[-self.LIMIT:]
                self.seek(0); self.truncate(0)
                super().write('[Earlier output omitted]\n' + tail)
        return len(value)

    def snapshot(self):
        with self.lock:
            return self.getvalue()


def operation(screen, action, args, lang='en'):
    title = LABELS[ACTIONS.index(action)]
    output = OperationOutput()
    output.write('Starting...\n')
    outcome = ['Completed']
    original_command = console.core.command

    def captured_command(argv, **kwargs):
        kwargs['capture'] = True
        return original_command(argv, **kwargs)

    def worker():
        try:
            console.core.command = captured_command
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                console.execute(action, args)
        except BaseException as error:
            outcome[0] = 'Failed'
            detail = str(error)
            if isinstance(error, subprocess.CalledProcessError):
                detail = error.stderr or error.stdout or str(error)
                if isinstance(detail, bytes):
                    detail = detail.decode(errors='replace')
            output.write('\nFailed: ' + detail.strip() + '\n')
        finally:
            console.core.command = original_command
            args.password = None

    task = threading.Thread(target=worker, name='weroxy-management')
    offset = 10**9; follow = True
    # Signal handling belongs to the main thread. A running lifecycle stage
    # finishes safely while the UI still responds to resize and scrolling.
    with console.critical_operation():
        task.start(); screen.timeout(100)
        try:
            while True:
                running = task.is_alive()
                offset = result(screen, title, output.snapshot(), running, 10**9 if follow else offset, outcome[0] if not running else '')
                key = read_key(screen, timeout=100)
                if running and action == 'update' and key in (27, ord('q')) and not args.update_installing.is_set():
                    args.update_cancel.set()
                    output.write('Cancelling download; current service is unchanged.\n')
                if not running and key in (10, 13, 27, ord('q'), curses.KEY_ENTER):
                    break
                if key in (curses.KEY_UP, curses.KEY_PPAGE):
                    follow = False
                    offset -= 1 if key == curses.KEY_UP else max(1, screen.getmaxyx()[0]-5)
                elif key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                    follow = False
                    offset += 1 if key == curses.KEY_DOWN else max(1, screen.getmaxyx()[0]-5)
                elif key == curses.KEY_HOME:
                    follow = False; offset = 0
                elif key == curses.KEY_END:
                    follow = True
        finally:
            # Do not restore the terminal or start another operation mid-mutation.
            task.join()
            screen.timeout(-1)


def menu(screen, lang='en', notice=''):
    with contextlib.suppress(curses.error):
        curses.curs_set(0)
    screen.keypad(True)
    state = console.summary(); selected = 1 if state['installed'] else 0
    while True:
        screen.erase(); height, width = screen.getmaxyx()
        if height < 10 or width < 32:
            put(screen, 0, 0, 'Resize terminal; Esc/q: exit')
        else:
            put(screen, 0, 2, 'WeroxyServer  ' + state['version'], curses.A_BOLD | color(1))
            put(screen, 1, 2, ('Installed' if state['installed'] else 'Not installed') + ' / ' + state['health'], color(2 if state['health']=='healthy' else 1))
            put(screen, 2, 2, state['url'], curses.A_DIM)
            count = max(1, height-9); first = max(0, min(selected-count+1, len(ACTIONS)-count))
            for index in range(first, min(len(ACTIONS), first+count)):
                action = ACTIONS[index]; enabled = available(action, state)
                label = LABELS[index]
                if not enabled:
                    label += ' (already installed)' if action == 'install' else ' (install first)'
                attr = (curses.A_REVERSE | curses.A_BOLD) if index == selected else (0 if enabled else curses.A_DIM)
                put(screen, 4+index-first, 2, ('> ' if selected == index else '  ') + label, attr)
            description = notice or DESCRIPTIONS[selected]
            for row, line in enumerate(wrap(description, width-4)[:2], height-4):
                put(screen, row, 2, line, color(1))
            put(screen, height-1, 1, 'Up/Down: select   Enter: run   R: refresh   Esc/q: exit')
        screen.refresh()
        key = read_key(screen)
        if key in (ord('q'), 27):
            return
        if key in (curses.KEY_UP,curses.KEY_DOWN,curses.KEY_HOME,curses.KEY_END):
            notice = ''
            if key == curses.KEY_UP:selected = (selected-1) % len(ACTIONS)
            elif key == curses.KEY_DOWN:selected = (selected+1) % len(ACTIONS)
            elif key == curses.KEY_HOME:selected = 0
            else:selected = len(ACTIONS)-1
        elif key in (ord('r'), ord('R')):
            state = console.summary(); notice = 'Status refreshed.'
        elif key in (10, 13, curses.KEY_ENTER) and height >= 10 and width >= 32:
            action = ACTIONS[selected]
            if action == 'quit':
                return
            if not available(action, state):
                notice = 'Already installed: select Start.' if action == 'install' else 'Install the Server first.'
                continue
            try:
                args = parameters(screen, action)
            except Exception:
                notice = "Unable to check update. Check network access and try again."
                continue
            if args is not None:
                operation(screen, action, args)
                notice = ''
            else:
                notice = 'Cancelled. No changes saved.'
            state = console.summary()


def initialize(screen, lang, notice):
    if curses.has_colors():
        curses.start_color()
        with contextlib.suppress(curses.error):
            curses.use_default_colors()
            for number, foreground in [(1,curses.COLOR_CYAN),(2,curses.COLOR_GREEN),(3,curses.COLOR_RED)]:
                curses.init_pair(number,foreground,-1)
    menu(screen, lang, notice)


def run(lang='en', notice=''):
    console.normalize_locale()
    # Avoid the default one-second Esc delay when returning between screens.
    with contextlib.suppress(AttributeError, curses.error):
        curses.set_escdelay(25)
    try:
        curses.wrapper(initialize, 'en', notice)
    except curses.error:
        raise RuntimeError('Terminal unavailable; use ./manage --help or a supported TERM') from None
