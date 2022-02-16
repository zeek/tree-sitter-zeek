// Aliases that make things easier to read
prec_r = prec.right;
prec_l = prec.left;

// Helper for a list of items with at least one member, with configurable
// separator token and optional support for a final, dangling separator.
function list1(item, sep, allow_final_sep=false) {
    if ( allow_final_sep ) {
        return choice(
            item,
            seq(repeat1(seq(item, sep)), item),
            repeat1(seq(item, sep)));
    } else {
        return choice(
            item,
            seq(repeat1(seq(item, sep)), item));
    }
}

module.exports = grammar({
    name: 'zeek',

    rules: {
        source_file: $ => seq(
            repeat($.decl),
            repeat($.stmt),
        ),

        decl: $ => choice(
            $.module_decl,
            $.export_decl,
            $.global_decl,
            $.option_decl,
            $.const_decl,
            $.redef_decl,
            $.redef_enum_decl,
            $.redef_record_decl,
            $.type_decl,
            $.func_decl,
            $.preproc_directive,
        ),

        module_decl: $ => seq('module', $.id, ';'),
        export_decl: $ => seq('export', '{', repeat($.decl), '}'),

        // A change here over Zeek's parser: we make the combo of init class
        // and initializer jointly optional, instead of individually. Helps
        // avoid ambiguity.
        global_decl: $ => seq('global', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
        option_decl: $ => seq('option', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
        const_decl: $ => seq('const', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
        redef_decl: $ => seq('redef', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),

        redef_enum_decl: $ => seq('redef', 'enum', $.id, '+=', '{', $.enum_body, '}', ';'),
        redef_record_decl: $ => seq('redef', 'record', $.id, '+=', '{', repeat($.type_spec), '}', optional($.attr_list), ';'),
        type_decl: $ => seq('type', $.id, ':', $.type, optional($.attr_list), ';'),
        func_decl: $ => seq($.func_hdr, repeat($.preproc_directive), $.func_body),

        stmt: $ => choice(
            // TODO: @no-test support
            seq('{', optional($.stmt_list), '}'),
            seq('print', $.expr_list, ';'),
            seq('event', $.event_hdr, ';'),
            prec_r(seq('if', '(', $.expr, ')', $.stmt, optional(seq('else', $.stmt)))),
            seq('switch', $.expr, '{', optional($.case_list), '}'),
            seq('for', '(', $.id, optional(seq(',', $.id)), 'in', $.expr, ')', $.stmt),
            seq('for', '(', '[', list1($.id, ','), ']', optional(seq(',', $.id)), 'in', $.expr, ')', $.stmt),
            seq('while', '(', $.expr, ')', $.stmt),
            seq(choice('next', 'break', 'fallthrough'), ';'),
            seq('return', optional($.expr), ';'),
            seq(choice('add', 'delete'), $.expr, ';'),
            seq('local', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';'),
            // Precedence here works around ambiguity with similar global declaration:
            prec(-1, seq('const', $.id, optional(seq(':', $.type)), optional($.initializer), optional($.attr_list), ';')),
            // Associativity here works around theoretical ambiguity if "when" nested:
            prec_r(seq(
                optional('return'),
                'when', optional($.capture_list), '(', $.expr, ')', $.stmt,
                optional(seq('timeout', $.expr, '{', optional($.stmt_list), '}')),
            )),
            seq($.index_slice, '=', $.expr, ';'),
            seq($.expr, ';'),
            // Same ambiguity as above for 'const'
            prec(-1, $.preproc_directive),
            ';',
        ),

        stmt_list: $ => repeat1($.stmt),

        case_list: $ => repeat1(
            choice(
                seq('case', $.expr_list, ':', optional($.stmt_list)),
                seq('case', $.case_type_list, ':', optional($.stmt_list)),
                seq('default', ':', optional($.stmt_list)),
            ),
        ),

        case_type_list: $ => list1(
            seq('type', $.type, optional(seq('as', $.id))), ','),

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
            seq('table', '[', list1($.type, ','), ']', 'of', $.type),
            seq('set', '[', list1($.type, ','), ']'),
            'time',
            'timer',
            seq('record', '{', repeat($.type_spec), '}'),
            seq('union', '{', list1($.type, ','), '}'),
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

        enum_body: $ => list1($.enum_body_elem, ',', true),

        enum_body_elem: $ => choice(
            seq($.id, '=', $.constant, optional($.deprecated)),
            seq($.id, optional($.deprecated)),
        ),

        deprecated: $ => choice(
            '&deprecated',
            seq('&deprecated', '=', 'const'),
        ),

        func_params: $ => choice(
            seq('(', $.formal_args, ')', optional(seq(':', $.type))),
        ),

        formal_args: $ => list1($.formal_arg, choice(';', ','), false),
        formal_arg: $ => seq($.id, ':', $.type, optional($.attr_list)),

        type_spec: $ => seq($.id, ':', $.type, optional($.attr_list), ';'),

        initializer: $ => seq(
            optional($.init_class),
            $.init,
        ),

        init_class: $ => prec_r(choice('=', '+=', '-=')),

        init: $ => choice(
            seq('{', '}'),
            seq('{', repeat(seq($.expr, ',')), $.expr, '}'),
            $.expr,
        ),

        attr_list: $ => prec_l(repeat1($.attr)),

        attr: $ => prec_l(choice(
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
            seq('&delete_func', '=', $.expr),
            seq('&expire_func', '=', $.expr),
            seq('&on_change', '=', $.expr),
            seq('&priority', '=', $.expr),
            seq('&read_expire', '=', $.expr),
            seq('&type_column', '=', $.expr),
            seq('&write_expire', '=', $.expr),
        )),

        // Compare to C precedence table at
        // https://en.cppreference.com/w/c/language/operator_precedence
        expr: $ => choice(
            prec_l(7, seq($.expr, '[', $.expr_list, ']')),
            prec_l(7, seq($.expr, $.index_slice)),
            prec_l(7, seq($.expr, '$', $.id)),

            prec_r(6, seq('|', $.expr, '|')),
            prec_r(6, seq('++', $.expr)),
            prec_r(6, seq('--', $.expr)),
            prec_r(6, seq('!', $.expr)),
            prec_r(6, seq('~', $.expr)),
            prec_r(6, seq('-', $.expr)),
            prec_r(6, seq('+', $.expr)),
            prec_l(6, seq($.expr, 'as', $.type)),
            prec_l(6, seq($.expr, 'is', $.type)),

            prec_l(5, seq($.expr, '*', $.expr)),
            prec_l(5, seq($.expr, '/', $.expr)),
            prec_l(5, seq($.expr, '%', $.expr)),

            prec_l(4, seq($.expr, '+', $.expr)),
            prec_l(4, seq($.expr, '-', $.expr)),

            prec_l(4, seq($.expr, '<', $.expr)),
            prec_l(4, seq($.expr, '<=', $.expr)),
            prec_l(4, seq($.expr, '>', $.expr)),
            prec_l(4, seq($.expr, '>=', $.expr)),

            prec_l(4, seq($.expr, '==', $.expr)),
            prec_l(4, seq($.expr, '!=', $.expr)),

            prec_l(4, seq($.expr, '&', $.expr)),
            prec_l(4, seq($.expr, '^', $.expr)),
            prec_l(4, seq($.expr, '|', $.expr)),
            prec_l(4, seq($.expr, '&&', $.expr)),
            prec_l(4, seq($.expr, '||', $.expr)),
            prec_r(4, seq($.expr, '?', $.expr, ':', $.expr)),
            prec_l(4, seq($.expr, 'in', $.expr)),
            prec_l(4, seq($.expr, '!', 'in', $.expr)),

            prec_r(3, seq($.expr, '=', $.expr)),
            prec_r(3, seq($.expr, '-=', $.expr)),
            prec_r(3, seq($.expr, '+=', $.expr)),

            prec(2, seq('$', $.id, '=', $.expr)),
            prec(2, seq('$', $.id, $.begin_lambda, '=', $.func_body)),

            prec_l(1, seq('[', optional($.expr_list), ']')),
            prec_l(1, seq('record', '(', $.expr_list, ')')),
            prec_l(1, seq('table', '(', optional($.expr_list), ')', optional($.attr_list))),
            prec_l(1, seq('set', '(', optional($.expr_list), ')', optional($.attr_list))),
            prec_l(1, seq('vector', '(', optional($.expr_list), ')')),
            prec_l(1, seq($.expr, '(', optional($.expr_list), ')')),

            $.id,
            $.constant,
            $.pattern,

            seq('(', $.expr, ')'),
            seq('copy', '(', $.expr, ')'),
            prec_r(seq('hook', $.expr)),
            seq($.expr, '?$', $.id),
            seq('schedule', $.expr, '{', $.event_hdr, '}'),
            seq('function', $.begin_lambda, $.func_body),

            // Lower precedence here to favor local-variable statements
            prec_r(-1, seq('local', $.id, '=', $.expr)),
        ),

        expr_list: $ => list1($.expr, ','),

        constant: $ => choice(
            // Associativity here resolves ambiguity with division
            prec_l(seq($.ipv4, optional(seq('/', /[0-9]+/)))),
            prec_l(seq($.ipv6, optional(seq('/', /[0-9]+/)))),
            $.hostname,
            'T',
            'F',
            $.hex,
            $.port,
            $.interval,
            $.string,
            $.floatp,
            prec(-10, $.integer),
        ),

        func_hdr: $ => choice($.func, $.hook, $.event),

        // Precedences here are to avoid ambiguity with related expressions
        func: $ => prec(1, seq('function', $.id, $.func_params, optional($.attr_list))),
        hook: $ => prec(1, seq('hook', $.id, $.func_params, optional($.attr_list))),
        event: $ => seq(optional('redef'), 'event', $.id, $.func_params, optional($.attr_list)),

        func_body: $ => seq('{', optional($.stmt_list), '}'),

        // Precedence here is to disambiguate other interpretations of the colon
        // and type, arising in expressions.
        func_params: $ => prec_l(
            seq('(', optional($.formal_args), ')', optional(seq(':', $.type)))
        ),

        index_slice: $ => seq('[', optional($.expr), ':', optional($.expr), ']'),

        begin_lambda: $ => seq(optional($.capture_list), $.func_params),

        capture_list: $ => seq('[', list1($.capture, ',', false), ']'),

        capture: $ => seq(optional('copy'), $.id),

        // The "preprocessor" directives. We include more than conditionals here.
        preproc_directive: $ => choice(
            seq('@deprecated', optional('('), $.string, optional(')')),
            seq('@load', $.file),
            seq('@load-sigs', $.file),
            seq('@load-plugin', $.id),
            seq('@unload', $.file),
            seq('@prefixes', choice('=', '+='), $.file),
            seq('@if', '(', $.expr, ')'),
            seq('@ifdef', '(', $.id, ')'),
            seq('@ifndef', '(', $.id, ')'),
            '@endif',
            '@else',
        ),

        // These directives return strings.
        string_directive: $ => choice(
            '@DIR',
            '@FILENAME',
        ),

        event_hdr: $ => seq($.id, '(', optional($.expr_list), ')'),

        id: $ => /[A-Za-z_][A-Za-z_0-9]*(::[A-Za-z_][A-Za-z_0-9]*)*/,
        file: $ => /[^ \t\r\n]+/,
        pattern: $ => /\/((\\\/)?[^\r\n\/]?)*\/i?/,

        // https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
        //
        // This is technically more narrow than Zeek's own IPv6 regex in a few
        // specific cases (IPv6-embedded v4 comes to mind, where Zeek accepts
        // technically invalid strings). Might want to move to Zeek's regex, for
        // consistency.
        //
        ipv6: $ => /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/,
        ipv4: $ => /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/,

        port: $ => /[0-9]+\/(tcp|udp|icmp|unknown)/,

        integer: $ => /[0-9]+/,
        floatp: $ => /(([0-9]*\.?[0-9]+)|([0-9]+\.[0-9]*))([eE][-+]?[0-9]+)?/,
        hex: $ => /0x[0-9a-fA-F]+/,

        // For some reason I need to call out integers as a choice here
        // explicitly -- floatp's ability to parse an integer doesn't trigger.
        interval: $ => seq(choice($.integer, $.floatp), $.time_unit),
        time_unit: $ => /(day|hr|min|sec|msec|usec)s?/,

        // We require hostnames to have a dot. This is a departure from Zeek,
        // but one that avoids several annoying confusions with other constants.
        hostname: $ => /([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z][A-Za-z0-9\-]*/,

        // Plain string characters or escape sequences, wrapped in double-quotes.
        string: $ => choice(
            /"([^\\\r\n\"]|\\([^\r\n]|[0-7]+|x[0-9a-fA-F]+))*"/,
            $.string_directive,
        ),
        
        minor_comment: $ => /#[^#][^\r\n]*/,

        // Zeekygen comments come in three flavors: a head one at the beginning
        // of a script (##!), one that refers to the previous node (##<), and
        // ones that refer to the subsequent one. Note that we skip the final
        // newline.
        zeekygen_head_comment: $ => /##![^\r\n]*/,
        zeekygen_prev_comment: $ => /##<[^\r\n]*/,
        zeekygen_next_comment: $ => /##[^\r\n]*/,

        // We track newlines explicitly -- this gives us the ability to honor
        // existing formatting in select places.
        nl: $ => /\r?\n/,
    },

    'extras': $ => [
        /[ \t]+/,
        $.nl,
        $.minor_comment,
        $.zeekygen_head_comment,
        $.zeekygen_prev_comment,
        $.zeekygen_next_comment,
    ],
});
