# bux has no Windows product. This file must exist so
# irm https://sh.qntx.org/bux/ps | iex does not fall through to the
# default one-binary template.
Write-Error 'bux does not support Windows'
exit 1
