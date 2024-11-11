# Запуск сканнеров
- gitleaks
- gosec
- horusec
- insider

# Запуск скриптом
python -i target/dir/for/scan -o output/dir -u user_docker -p password_docker

1. Делает docker login
2. Качает images сканеров или ищет локально 
3. Запускает по очереди сканеры
4. Выводит {scaner_name}_output.json
5. мержит jsonЫ в один

   TODO:
   1. Запустить сканирования в трединге
   2. Добавить выбор формата результата (трабл: не все поддерживают SARIF для более детального анализа)
   3. Сделать правки для линукса + обработки ошибок
