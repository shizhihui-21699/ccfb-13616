# 二层包装：base64 还原后交给 eval
DECODED=$(echo "aW1wb3J0IHN1YnByb2Nlc3M7IHByaW50KCJkZWNvZGVkIHBheWxvYWQiKQ==" | base64 -d)
eval "$DECODED"
