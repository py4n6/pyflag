""" This module implements a javascript parser. Our goals are:

- Be very tolerant of errors

  Produce a parse tree (i.e. we dont evaluate anything). The parse
  tree is similar to a HTML DOM and has the same methods. Tags called
  function (attribute name), string, variable (attribute name) are
  supported.

- The parse tree is not designed to be that accurate (i.e. we dont
  need to evaluate the code). The most important thing is to ensure
  that data structures are properly extracted. This parser is mostly
  used for evaluating json and other webmail.

  The main advantage of this parser over a regular json parser is that
  a partial parse tree is generated, even if the file is truncated or
  heavily corrupted - the parser resyncs to the input stream to
  produce some kind of AST even for heavily corrupted files. This
  increases the likelyhood that the AST can be useful even if the
  files are corrupted (e.g. carved).
"""

import lexer, HTML, re, sys, pdb

class JSParser(lexer.Lexer):
    state = "GLOBAL"
    flags = re.I
    
    ## This is the currently parsed object
    current = None

    tokens = [
        ## String handling
        [ "STRING", '"', "POP_STATE,FUNCTION_END", None],
        [ "STRING", r"\\u(....)", "STRING_UNICODE_ESCAPE", None],
        [ "STRING", r"\\.", "STRING_ESCAPE", None],
        [ "STRING", r"[^\"\\]+", "STRING_ADD", None],

        ## Function and array handling
        [ ".", ",", "NEXT_ARG", None],
        [ ".", "\)", "POP_STATE,FUNCTION_END", None],

        ## Can be valid anywhere
        [ ".", "new", 'IGNORE', None ],
        [ ".", r"([a-zA-Z0-9.]+)\s*\(", "PUSH_STATE,FUNCTION", "FUNCTION" ],
        [ '.', '[a-zA-Z]+', "VARIABLE", None],
        [ ".", "[0-9]+", "INTEGER", None],
        [ ".", '"', "PUSH_STATE,STRING_START", "STRING"],
        [ ".", r"\[", "PUSH_STATE,ARRAY_START", "ARRAY"],
        [ ".", r"\]", "POP_STATE,FUNCTION_END", "ARRAY"],

        ## Whitespace:
        [ '.',';\s+', 'SPACE', None],

        ]

    def __init__(self, verbose=0):
        ## This is the root element - everything else will be attached
        ## to this:
        self.root = HTML.Tag(name='root', charset='utf8')
        self.stack = [self.root]
        lexer.Lexer.__init__(self, verbose)

    def FUNCTION(self, t, m):
        t = HTML.Tag(name="function", attributes=dict(name=m.group(1)))
        self.stack[-1].add_child(t)
        self.stack.append(t)

    def ARRAY_START(self, t, m):
        t = HTML.Tag(name="Array")
        self.stack[-1].add_child(t)
        self.stack.append(t)

    def INTEGER(self, t, m):
        self.current = int(m.group(0))

    def STRING_ESCAPE(self, t, m):
        self.current += m.group(0).decode("string_escape")

    def STRING_UNICODE_ESCAPE(self, t, m):
        self.current += m.group(0).decode("unicode_escape")

    def NEXT_ARG(self, t, m):
        t = self.stack[-1]
        if self.current is not None:
            t.add_child(self.current)
            self.current = None

    def FUNCTION_END(self, t, m):
        self.NEXT_ARG(t, m)
        self.stack.pop(-1)
        self.current = None

    def VARIABLE(self, t, m):
        t = HTML.Tag(name = "variable", attributes=dict(name=m.group(0)))
        self.current = t

    def STRING_START(self, t, m):
        t = HTML.Tag(name = "string")
        self.stack[-1].add_child(t)
        self.stack.append(t)
        self.current = u''

    def STRING_ADD(self, t, m):
        self.current += m.group(0)

if __name__=='__main__':
    try:
        parser = JSParser(verbose = 10)
        parser.feed(open(sys.argv[1]).read().decode("utf8"))

        while parser.next_token(): pass
        print parser.root.innerHTML().encode("utf8")
    except:
        raise
        pdb.post_mortem()
