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
            // Slight change here over Zeek's parser: we make the combo of init
            // class and initializer jointly optional:
            seq('global', $.id, optional(seq(':', $.type)), optional(seq($.init_class, $.init)), optional($.attr_list), ';'),
            seq('option', $.id, optional(seq(':', $.type)), optional(seq($.init_class, $.init)), optional($.attr_list), ';'),
            seq('const', $.id, optional(seq(':', $.type)), optional(seq($.init_class, $.init)), optional($.attr_list), ';'),
            seq('redef', $.id, optional(seq(':', $.type)), optional(seq($.init_class, $.init)), optional($.attr_list), ';'),
            seq('redef', 'enum', $.id, '+=', '{', $.enum_body, '}', ';'),
            seq('redef', 'record', $.id, '+=', '{', repeat($.type_decl), '}', optional($.attr_list), ';'),
            seq('type', $.id, ':', $.type, optional($.attr_list), ';'),
            seq($.func_hdr, repeat($.conditional), $.func_body),
            seq($.conditional),
        ),
        
        stmt: $ => choice(
            // TODO
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

        enum_body: $ => repeat1(
            seq(optional(seq($.enum_body_elem, ',')), $.enum_body_elem),
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
            seq('(', $.formal_args, ')', ':', $.type),
            seq('(', $.formal_args, ')'),
        ),
        
        formal_args: $ => choice(
            $.formal_args_decl_list,
            seq($.formal_args_decl_list, ';'),
        ),

        formal_args_decl_list: $ => choice(
            seq($.formal_args_decl_list, ';', $.formal_args_decl),
            seq($.formal_args_decl_list, ',', $.formal_args_decl),
            $.formal_args_decl),
        
        formal_args_decl: $ => seq($.id, ':', optional($.attr_list)),
        
        type_decl: $ => seq($.id, ':', $.type, optional($.attr_list), ';'),
        
        init_class: $ => choice('=', '+=', '-='),

        init: $ => choice(
            seq('{', '}'),
            seq('{', optional(seq($.expr, ',')), $.expr, '}'),
            $.expr,
        ),

        attr_list: $ => prec.l(0, repeat1(
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
                seq('&deprecated', '=', 'const'),
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
            seq('(', $.expr, ')'),
            seq('copy', '(', $.expr, ')'),
            
            prec(5, seq($.expr, '[', $.expr_list, ']')),
            prec(5, seq($.expr, '[', optional($.expr), ':', optional($.expr), ']')),
            prec(5, seq($.expr, '$', $.id)),
            
            prec.r(4, seq('++', $.expr)),
            prec.r(4, seq('--', $.expr)),
            prec.r(4, seq('!', $.expr)),
            prec.r(4, seq('~', $.expr)),
            prec.r(4, seq('-', $.expr)),
            prec.r(4, seq('+', $.expr)),
            
            prec.l(3, seq($.expr, '*', $.expr)),
            prec.l(3, seq($.expr, '/', $.expr)),
            prec.l(3, seq($.expr, '%', $.expr)),

            prec.l(2, seq($.expr, '+', $.expr)),
            prec.l(2, seq($.expr, '-', $.expr)),
            
            prec.l(2, seq($.expr, '<', $.expr)),
            prec.l(2, seq($.expr, '<=', $.expr)),
            prec.l(2, seq($.expr, '>', $.expr)),
            prec.l(2, seq($.expr, '>=', $.expr)),

            prec.l(2, seq($.expr, '==', $.expr)),
            prec.l(2, seq($.expr, '!=', $.expr)),
            
            prec.l(2, seq($.expr, '&', $.expr)),
            prec.l(2, seq($.expr, '^', $.expr)),
            prec.l(2, seq($.expr, '|', $.expr)),
            prec.l(2, seq($.expr, '&&', $.expr)),
            prec.l(2, seq($.expr, '||', $.expr)),
            prec.r(2, seq($.expr, '?', $.expr, ':', $.expr)),
            prec.l(2, seq($.expr, 'in', $.expr)),
            prec.l(2, seq($.expr, '!', 'in', $.expr)),
            
            prec.r(1, seq($.expr, '=', $.expr)), 
            prec.r(1, seq($.expr, '-=', $.expr)), 
            prec.r(1, seq($.expr, '+=', $.expr)),

            prec(0, seq('$', $.id, '=', $.expr)),
            prec(0, seq('$', $.id, $.begin_lambda, '=', $.lambda_body)),
            
            prec.l(0, seq('[', optional($.expr_list), ']')),
            prec.l(0, seq('record', '(', $.expr_list, ')')),
            prec.l(0, seq('table', '(', optional($.expr_list), ')', optional($.attr_list))),
            prec.l(0, seq('set', '(', optional($.expr_list), ')', optional($.attr_list))),
            prec.l(0, seq('vector', '(', optional($.expr_list), ')')),
            // XXX prec.l(0, seq($.expr, '(', optional($.expr_list), ')')),
            
            prec(0, seq('local', $.id, '=', $.expr)),
            // TODO
        ),

        expr_list: $ => seq(optional(seq($.expr, ',')), $.expr),
                 
        func_hdr: $ => choice(
            seq('function', $.id, $.func_params, optional($.attr_list)),
            seq('event', $.id, $.func_params, optional($.attr_list)),
            seq('hook', $.id, $.func_params, optional($.attr_list)),
            seq('redef', 'event', $.id, $.func_params, optional($.attr_list)),
        ),

        func_body: $ => seq('{', repeat($.stmt), '}'),

        func_params: $ => seq('(', optional($.formal_args), ')', optional(seq(':', $.type))),

        begin_lambda: $ => seq(optional($.capture_list), $.func_params),

        capture_list: $ => repeat1(
            seq(optional(seq($.capture, ',')), $.capture),
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
        
        id: $ => /[A-Za-z_][A-Za-z_0-9]*(::[A-Za-z_][A-Za-z_0-9]*)*/,
        file: $ => /[^ \t\r\n]+/,    
    },
    
    'extras': $ => [
        /[ \t\n/]+/,
        /#.*\n/,
    ],
    
    'conflicts': $ => [
        [$.source_file],
    ],
});
