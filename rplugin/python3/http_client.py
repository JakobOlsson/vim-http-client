import json
import re
import requests

import pynvim

# vim = attach('socket', path='/tmp/nvim')

METHOD_REGEX = re.compile('^(GET|POST|DELETE|PUT|HEAD|OPTIONS|PATCH) (.*)$')
HEADER_REGEX = re.compile('^([^()<>@,;:\<>/\[\]?={}]+):\\s*(.*)$')
VAR_REGEX = re.compile('^# ?(:[^: ]+)\\s*=\\s*(.+)$')
GLOBAL_VAR_REGEX = re.compile('^# ?(\$[^$ ]+)\\s*=\\s*(.+)$')
FILE_REGEX = re.compile("!((?:file)|(?:(?:content)))\((.+)\)")
JSON_REGEX = re.compile("(javascript|json)$", re.IGNORECASE)



def replace_vars(string, variables):
    for var, val in variables.items():
        string = string.replace(var, val)
    return string


def is_comment(s):
    return s.startswith('#')


def do_request(block, buf, verify_ssl):
    variables = dict((m.groups() for m in (GLOBAL_VAR_REGEX.match(l) for l in buf) if m))
    variables.update(dict((m.groups() for m in (VAR_REGEX.match(l) for l in block) if m)))

    block = [line for line in block
             if not is_comment(line) and line.strip() != '']

    if len(block) == 0:
        print('Request was empty.')
        return

    method_url = block.pop(0)
    method_url_match = METHOD_REGEX.match(method_url)
    if not method_url_match:
        print('Could not find method or URL!')
        return

    method, url = method_url_match.groups()
    url = replace_vars(url, variables)
    url = url.strip()

    headers = {}
    while len(block) > 0:
        header_match = HEADER_REGEX.match(block[0])
        if header_match:
            block.pop(0)
            header_name, header_value = header_match.groups()
            headers[header_name] = replace_vars(header_value, variables)
        else:
            break

    data = [replace_vars(l, variables) for l in block]
    files = None
    if all(['=' in l for l in data]):
        # Form data: separate entries into data dict, and files dict
        key_value_pairs = dict([l.split('=', 1) for l in data])

        def to_file(expr):
            type, arg = FILE_REGEX.match(expr).groups()
            arg = arg.replace('\\(', '(').replace('\\)', ')')
            return open(arg, 'rb') if type == 'file' else (arg)

        files = dict([(k, to_file(v)) for (k, v) in key_value_pairs.items() if FILE_REGEX.match(v)])
        data = dict([(k, v) for (k, v) in key_value_pairs.items() if not FILE_REGEX.match(v)])
    else:
        # Straight data: just send it off as a string.
        data = '\n'.join(data)

    if not verify_ssl:
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    json_data = None
    if headers.get('Content-Type') == 'application/json':
        json_data = json.loads(data)
        data = None

    response = requests.request(
        method,
        url,
        verify=verify_ssl,
        headers=headers,
        data=data,
        files=files,
        json=json_data
    )
    content_type = response.headers.get('Content-Type', '').split(';')[0]

    response_body = response.text
    if JSON_REGEX.search(content_type):
        content_type = 'application/json'
        try:
            response_body = json.dumps(
                json.loads(response.text), sort_keys=True, indent=2,
                separators=(',', ': '),
                ensure_ascii=vim.eval('g:http_client_json_escape_utf') == '1')
        except ValueError:
            pass

    display = (
        response_body.split('\n') +
        ['', '// status code: %s' % response.status_code] +
        ['// %s: %s' % (k, v) for k, v in response.headers.items()]
    )

    return display, content_type


# Vim methods.

@pynvim.plugin
class Main(object):
    def __init__(self, vim):
        self.vim = vim
        self.BUFFER_NAME = '__HTTP_Client_Response__'

        # self.verify_ssl = vim.eval('g:http_client_verify_ssl') == '1'
        self.verify_ssl = 0

    def vim_filetypes_by_content_type(self):
        return {
            'application/json': self.vim.eval('g:http_client_json_ft'),
            'application/xml': 'xml',
            'text/html': 'html'
        }

    def find_block(self, buf, line_num):
        length = len(buf)
        is_buffer_terminator = lambda s: s.strip() == ''

        block_start = line_num
        while block_start > 0 and not is_buffer_terminator(buf[block_start]):
            block_start -= 1

        block_end = line_num
        while block_end < length and not is_buffer_terminator(buf[block_end]):
            block_end += 1

        return buf[block_start:block_end + 1]

    def open_scratch_buffer(self, contents, filetype):
        previous_window = self.vim.current.window
        existing_buffer_window_id = self.vim.eval(
            'bufwinnr("%s")' % self.BUFFER_NAME
        )
        if existing_buffer_window_id == '-1':
            if self.vim.eval('g:http_client_result_vsplit') == '1':
                split_cmd = 'vsplit'
            else:
                split_cmd = 'split'
            self.vim.command(
                'rightbelow %s %s' % (
                    split_cmd, self.BUFFER_NAME
                )
            )
            self.vim.command('setlocal buftype=nofile nospell')
        else:
            self.vim.command('%swincmd w' % existing_buffer_window_id)

        self.vim.command('set filetype=%s' % filetype)
        self.write_buffer(contents, self.vim.current.buffer)

        if self.vim.eval('g:http_client_focus_output_window') != '1':
            self.vim.current.window = previous_window

    @pynvim.function('DoRequestFromBuffer')
    def do_request_from_buffer(self, args):
        win = self.vim.current.window
        line_num = win.cursor[0] - 1
        block = self.find_block(win.buffer, line_num)
        result = do_request(block, win.buffer, self.verify_ssl)
        if result:
            response, content_type = result
            vim_ft = self.vim_filetypes_by_content_type(
            ).get(content_type, 'text')
            self.open_scratch_buffer(response, vim_ft)

    def write_buffer(self, contents, buffer):
        if self.vim.eval('g:http_client_preserve_responses') == '1':
            if len(buffer):
                buffer[0:0] = [""]
            buffer[0:0] = contents
            self.vim.command('0')
        else:
            buffer[:] = contents
