@echo off
copy /y readme.md docfx\docs\readme.md
cd docfx
docfx docfx.json --serve
