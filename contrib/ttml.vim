" TTML (mod_dtcl) syntax file.
" Language:	Tcl + HTML
" Maintainer:	Wojciech Kocjan <zoro@nowiny.net>
" Filenames:	*.ttml

if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

if !exists("main_syntax")
  let main_syntax = 'ttml'
endif

if version < 600
  so <sfile>:p:h/html.vim
else
  runtime! syntax/html.vim
  unlet b:current_syntax
endif


syntax include @tclTop syntax/tcl.vim

syntax region ttmlTcl keepend matchgroup=Delimiter start="<?" end="?>" contains=@tclTop

let b:current_syntax = "ttml"

if main_syntax == 'ttml'
  unlet main_syntax
endif
