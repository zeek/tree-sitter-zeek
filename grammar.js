// Aliases that make things easier to read
prec.r = prec.right;
prec.l = prec.left;

module.exports = grammar({
    name: 'Zeek',

    rules: {
        source_file: $ => seq(
            repeat($.decl),
            repeat($.stmt),
        ),

        preproc: $ => choice(
            $.atload,
        ),

        atload: $ => seq('@load', $.file),

        decl: $ => choice(
            seq('module', $.id, ';'),
            seq('export', '{', repeat($.decl), '}'),
            // A change here over Zeek's parser: we make the combo of init class
            // and initializer jointly optional, instead of individually. Helps
            // avoid ambiguity.
            seq('global', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
            seq('option', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
            seq('const', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
            seq('redef', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
            seq('redef', 'enum', $.id, '+=', '{', $.enum_body, '}', ';'),
            seq('redef', 'record', $.id, '+=', '{', repeat($.type_decl), '}', optional($.attr_list), ';'),
            seq('type', $.id, ':', $.type, optional($.attr_list), ';'),
            seq($.func_hdr, repeat($.conditional), $.func_body),
            seq($.conditional),
        ),

        stmt: $ => choice(
            // TODO: @no-test support
            seq('{', repeat($.stmt), '}'),
            seq('print', $.expr_list, ';'),
            seq('event', $.event, ';'),
            prec.r(seq('if', '(', $.expr, ')', $.stmt, optional(seq('else', $.stmt)))),
            seq('switch', $.expr, '{', optional($.case_list), '}'),
            seq('for', '(', $.id, optional(seq(',', $.id)), 'in', $.expr),
            seq('for', '(', '[', repeat($.id), ']', optional(seq(',', $.id)), 'in', $.expr, ')'),
            seq('while', '(', $.expr, ')', $.stmt),
            seq(choice('next', 'break', 'fallthrough'), ';'),
            seq('return', optional($.expr), ';'),
            seq(choice('add', 'delete'), $.expr, ';'),
            seq('local', $.id, optional($.type), optional($.initializer), optional($.attr_list), ';'),
            // Precedence here works around ambiguity with similar global declaration:
            prec(-1, seq('const', $.id, optional($.type), optional($.initializer), optional($.attr_list), ';')),
            // Associativity here works around theoretical ambiguity if "when" nested:
            prec.r(seq(
                optional('return'),
                'when', '(', $.expr, ')', $.stmt,
                optional(seq('timeout', $.expr, '{', repeat($.stmt), '}')),
            )),
            seq($.index_slice, '=', $.expr, ';'),
            // $.expr, XXX
            ';',
            // Same ambiguity as above for 'const'
            prec(-1, $.conditional),
        ),

        case_list: $ => repeat1(
            choice(
                seq('case', $.expr_list, ':', repeat($.stmt)),
                seq('case', $.case_type_list, ':', repeat($.stmt)),
                seq('default', ':', repeat($.stmt)),
            ),
        ),

        case_type_list: $ => repeat1(
            seq('type', $.type, optional(seq('as', $.id))),
        ),

        type: $ => choice(
            'addr',
            'any',
            'bool',
            'count',
            'double',
            'int',
            'interval',
            'string',
            'subnet',
            'pattern',
            'port',
            seq('table', '[', repeat1($.type), ']', 'of', $.type),
            seq('set', '[', repeat1($.type), ']'),
            'time',
            'timer',
            seq('record', '{', repeat($.type_decl), '}'),
            seq('union', '{', repeat($.type), '}'),
            seq('enum', '{', $.enum_body, '}'),
            'list',
            seq('list', 'of', $.type),
            seq('vector', 'of', $.type),
            seq('function', $.func_params),
            seq('event', '(', optional($.formal_args), ')'),
            seq('hook', '(', optional($.formal_args), ')'),
            seq('file', 'of', $.type),
            'file',
            seq('opaque', 'of', $.id),
            $.id,
        ),

        // This seems a good pattern for expressing sequences of one or more,
        // with a given separator or set of separators. Could provide this as a
        // new function to make more legible.
        enum_body: $ => repeat1(
            seq(repeat(seq($.enum_body_elem, ',')), $.enum_body_elem),
        ),

        enum_body_elem: $ => choice(
            seq($.id, '=', 'const', optional($.deprecated)),
            seq($.id, '=', '-', 'const'),
            seq($.id, optional($.deprecated)),
        ),

        deprecated: $ => choice(
            '&deprecated',
            seq('&deprecated', '=', 'const'),
        ),

        func_params: $ => choice(
            seq('(', $.formal_args, ')', optional(seq(':', $.type))),
        ),

        formal_args: $ => repeat1(
            seq(repeat(seq($.formal_arg, choice(';', ','))), $.formal_arg),
        ),

        formal_arg: $ => seq($.id, ':', $.type, optional($.attr_list)),

        type_decl: $ => seq($.id, ':', $.type, optional($.attr_list), ';'),

        initializer: $ => seq(
            $.init_class,
            $.init,
        ),

        init_class: $ => choice('=', '+=', '-='),

        init: $ => choice(
            seq('{', '}'),
            seq('{', repeat(seq($.expr, ',')), $.expr, '}'),
            $.expr,
        ),

        attr_list: $ => prec.l(repeat1(
            choice(
                '&broker_store_allow_complex_type',
                '&deprecated',
                '&error_handler',
                '&is_assigned',
                '&is_used',
                '&log',
                '&optional',
                '&raw_output',
                '&redef',
                seq('&add_func', '=', $.expr),
                seq('&backend', '=', $.expr),
                seq('&broker_store', '=', $.expr),
                seq('&create_expire', '=', $.expr),
                seq('&default', '=', $.expr),
                seq('&deprecated', '=', $.string),
                seq('&del_func', '=', $.expr),
                seq('&expire_func', '=', $.expr),
                seq('&on_change', '=', $.expr),
                seq('&priority', '=', $.expr),
                seq('&read_expire', '=', $.expr),
                seq('&type_column', '=', $.expr),
                seq('&write_expire', '=', $.expr),
            ),
        )),

        // Compare to C precedence table at
        // https://en.cppreference.com/w/c/language/operator_precedence
        expr: $ => choice(
            prec.l(7, seq($.expr, '[', $.expr_list, ']')),
            prec.l(7, seq($.expr, $.index_slice)),
            prec.l(7, seq($.expr, '$', $.id)),

            prec.r(6, seq('++', $.expr)),
            prec.r(6, seq('--', $.expr)),
            prec.r(6, seq('!', $.expr)),
            prec.r(6, seq('~', $.expr)),
            prec.r(6, seq('-', $.expr)),
            prec.r(6, seq('+', $.expr)),
            prec.l(6, seq($.expr, 'as', $.type)),
            prec.l(6, seq($.expr, 'is', $.type)),

            prec.l(5, seq($.expr, '*', $.expr)),
            prec.l(5, seq($.expr, '/', $.expr)),
            prec.l(5, seq($.expr, '%', $.expr)),

            prec.l(4, seq($.expr, '+', $.expr)),
            prec.l(4, seq($.expr, '-', $.expr)),

            prec.l(4, seq($.expr, '<', $.expr)),
            prec.l(4, seq($.expr, '<=', $.expr)),
            prec.l(4, seq($.expr, '>', $.expr)),
            prec.l(4, seq($.expr, '>=', $.expr)),

            prec.l(4, seq($.expr, '==', $.expr)),
            prec.l(4, seq($.expr, '!=', $.expr)),

            prec.l(4, seq($.expr, '&', $.expr)),
            prec.l(4, seq($.expr, '^', $.expr)),
            prec.l(4, seq($.expr, '|', $.expr)),
            prec.l(4, seq($.expr, '&&', $.expr)),
            prec.l(4, seq($.expr, '||', $.expr)),
            prec.r(4, seq($.expr, '?', $.expr, ':', $.expr)),
            prec.l(4, seq($.expr, 'in', $.expr)),
            prec.l(4, seq($.expr, '!', 'in', $.expr)),

            prec.r(3, seq($.expr, '=', $.expr)),
            prec.r(3, seq($.expr, '-=', $.expr)),
            prec.r(3, seq($.expr, '+=', $.expr)),

            prec(2, seq('$', $.id, '=', $.expr)),
            prec(2, seq('$', $.id, $.begin_lambda, '=', $.lambda_body)),

            prec.l(1, seq('[', optional($.expr_list), ']')),
            prec.l(1, seq('record', '(', $.expr_list, ')')),
            prec.l(1, seq('table', '(', optional($.expr_list), ')', optional($.attr_list))),
            prec.l(1, seq('set', '(', optional($.expr_list), ')', optional($.attr_list))),
            prec.l(1, seq('vector', '(', optional($.expr_list), ')')),
            prec.l(1, seq($.expr, '(', optional($.expr_list), ')')),

            $.id,
            $.constant,
            $.pattern,

            seq('local', $.id, '=', $.expr),
            seq('(', $.expr, ')'),
            seq('copy', '(', $.expr, ')'),
            seq('hook', $.expr),
            // seq($.expr, '?$', $.id), XXX
            seq('schedule', $.expr, '{', $.event, '}'),
            seq('|', $.expr, '|'),

            // TODO anonymous_function,
        ),

        expr_list: $ => seq(repeat(seq($.expr, ',')), $.expr),

        constant: $ => choice(
            prec.l(seq($.ipv4, optional(seq('/', /[0-9]+/)))),
            prec.l(seq($.ipv6, optional(seq('/', /[0-9]+/)))),
            $.hostname,
            'T',
            'F',
            $.hex,
            $.port,
            $.interval,
            $.string,
            $.floatp,
            $.integer,
        ),

        func_hdr: $ => choice(
            seq('function', $.id, $.func_params, optional($.attr_list)),
            seq('event', $.id, $.func_params, optional($.attr_list)),
            seq('hook', $.id, $.func_params, optional($.attr_list)),
            seq('redef', 'event', $.id, $.func_params, optional($.attr_list)),
        ),

        func_body: $ => seq('{', repeat($.stmt), '}'),

        // Precedence here is to disambiguate other interpretations of the colon
        // and type, arising in expressions.
        func_params: $ => prec.l(
            seq('(', optional($.formal_args), ')', optional(seq(':', $.type)))
        ),

        index_slice: $ => seq('[', optional($.expr), ':', optional($.expr), ']'),

        begin_lambda: $ => seq(optional($.capture_list), $.func_params),

        capture_list: $ => repeat1(
            seq(repeat(seq($.capture, ',')), $.capture),
        ),

        capture: $ => seq(optional('copy'), $.id),

        lambda_body: $ => seq('{', repeat($.stmt), '}'),

        // The "preprocessor" options. We include @load here, which is handled
        // separately in Zeek's parser.
        conditional: $ => choice(
            seq('@load', $.file),
            seq('@if', '(', $.expr, ')'),
            seq('@ifdef', '(', $.id, ')'),
            seq('@ifndef', '(', $.id, ')'),
            '@endif',
            '@else',
        ),

        event: $ => seq($.id, '(', optional($.expr_list), ')'),

        id: $ => /[A-Za-z_][A-Za-z_0-9]*(::[A-Za-z_][A-Za-z_0-9]*)*/,
        file: $ => /[^ \t\r\n]+/,
        pattern: $ => /\/[^/\r\n]*\/i?/, // XXX this is likely too simplistic

        // Sigh ... https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        ipv6: $ => /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/,
        ipv4: $ => /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/,

        port: $ => /[0-9]+\/(tcp|udp|icmp|unknown)/,

        integer: $ => /[0-9]+/,
        floatp: $ => /[0-9]+\.[0-9]+/,
        hex: $ => /0x[0-9a-fA-F]+/,

        // Intervals can be expressed without whitespace, e.g. "24hrs", so we
        // can't handle number and unit as separate tokens. We treat the whole
        // thing as a regex.
        interval: $ => /[0-9]+(\.[0-9]+)?[ \t]*(day|hr|min|sec|msec|usec)s?/,

        hostname_part: $ => /[A-Za-z0-9][A-Za-z0-9\-]*/,
        hostname_tld: $ => /[A-Za-z][A-Za-z0-9\-]*/,
        hostname: $ => seq(repeat1(seq($.hostname_part, '.')), $.hostname_tld),

        // Plain string characters or escape sequences, wrapped in double-quotes.
        string: $ => /"([^\r\n"]|\\([^\r\n]|[0-7]+|x[0-9a-fA-F]+))*"/,
    },

    'extras': $ => [
        /[ \t\n/]+/,
        /#.*\n/,
    ],
});
