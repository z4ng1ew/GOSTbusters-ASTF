@echo off
echo 🚀 ЗАПУСК ДЕМОНСТРАЦИИ ХАКАТОНА (TEAM 179)
echo ==========================================

echo 🔧 Шаг 1: Сборка проекта...
call mvn clean package -q

echo.
echo 🔍 Шаг 2: Сканирование VBank (с плагинами)...
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar scan ^
  --config configs/vbank.yaml ^
  --output target/reports/vbank-report.html

echo.
echo 🔍 Шаг 3: Сканирование ABank...
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar scan ^
  --config configs/abank.yaml ^
  --output target/reports/abank-report.html

echo.
echo 🔍 Шаг 4: Сканирование SBank...
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar scan ^
  --config configs/sbank.yaml ^
  --output target/reports/sbank-report.html

echo.
echo 📊 Шаг 5: Генерация объединённого отчёта...
java -jar target/api-security-testing-framework-1.0-SNAPSHOT.jar scan-all ^
  --configs configs/vbank.yaml,configs/abank.yaml,configs/sbank.yaml ^
  --output target/reports/final-hackathon-report.pdf

echo.
echo ✅ ДЕМОНСТРАЦИЯ ЗАВЕРШЕНА!
echo 📁 Отчёты сохранены в: target/reports/
pause