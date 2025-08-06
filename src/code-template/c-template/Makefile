## 変数の定義
# コンパイラ
CC= cc
# コンパイルオプション
CFLAGS= -Wall
# 実行ファイル名
TARGET= main
# コンパイル対象のソースコード
SRCS= main.c
# オブジェクトファイル名
OBJS= $(SRCS:.c=.o)
# インクルードファイルのあるディレクトリパス
INCDIR=
# ライブラリファイルのあるディレクトリパス
LIBDIR=
# 追加するライブラリファイル
LIBS=

## ターゲットの定義
# ターゲットファイル生成
$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LIBDIR) $(LIBS)
	
# オブジェクトファイル生成
$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) $(INCDIR) -c $(SRCS)

# 全てを作成するターゲット
all: $(TARGET)

# .oファイル、実行ファイル、.dファイルを削除
.PHONY:	clean
clean:
	-rm -f $(OBJS) $(TARGET) *.d
