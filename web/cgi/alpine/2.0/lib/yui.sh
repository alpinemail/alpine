#!/bin/sh
if test ! -d "yui-2.9.0" ; then
  rm -rf yui
  echo "Downloading yui_2.9.0.zip. Wait...."
  wget -q http://yui.github.io/yui2/archives/yui_2.9.0.zip
  echo "Unpacking yui_2.9.0.zip..."
  unzip -q yui_2.9.0.zip
  echo "Removing yui_2.9.0.zip"
  rm -f yui_2.9.0.zip
  echo "Renaming yui to yui-2.9.0"
  mv yui yui-2.9.0
  echo "Creating symbolic link yui to yui-2.9.0"
  ln -s yui-2.9.0 yui
fi

