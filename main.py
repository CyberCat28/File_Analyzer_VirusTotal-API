import os
from scanner import Scanner

def print_menu():
    print("1. Проверить файл (локальный)\n2. Проверить URL-адрес\n3. Проверить по хешу (SHA-256)\n")

def format_results(result: dict):   # вывод результатов
    if "error" in result:
        print(f"\nОшибка: {result['error']}")
        if "note" in result:
            print(f"Примечание: {result['note']}")
        return

    if result.get("status") in ["uploaded", "scanning"]:
        print(f"\nСтатус: {result['message']}")
        print(f"ID анализа: {result.get('analysis_id')}")
        return

    if result.get("status") == "not_found":
        print(f"\nРезультат: {result['message']}")
        return

    stats = result.get("stats", {})
    print("\nРезультаты анализа")
    print(f"Malicious: {stats.get('malicious', 0)}")
    print(f"Suspicious: {stats.get('suspicious', 0)}")
    print(f"Harmless: {stats.get('harmless', 0)}")
    print(f"Undetected: {stats.get('undetected', 0)}")
    
    if result.get("type") == "url":
        print(f"Категория: {result.get('category', 'N/A')}")
    
    if result.get("malicious_details"):
        print("\nДетали угроз")
        for det in result['malicious_details']:
            print(f"Антивирус: {det['engine']} | Вердикт: {det['result']}")
    
    print(f"\nСсылка на отчет: {result.get('permalink', 'N/A')}")

def main():
    try:
        scanner = Scanner()
    except ValueError:
        print("Ошибка инициализации: Проверьте наличие файла .env и ключа API")
        return

    while True:
        print_menu()
        choice = input("Выберите тип проверки: ").strip()

        if choice == '1':
            file_path = input("Введите путь к файлу: ").strip()
            # убирание кавычек, если пользователь указал путь с ними
            file_path = file_path.strip('"').strip("'")
            
            if not os.path.exists(file_path):
                print("Ошибка: Файл не найден по указанному пути")
                continue
            
            try:
                result = scanner.check_file(file_path)
                format_results(result)
            except Exception as e:
                print(f"Непредвиденная ошибка: {e}")

        elif choice == '2':
            url = input("Введите URL-ссылку для проверки: ").strip()
            if not url.startswith(('http://', 'https://')):
                print("Предупреждение: URL-ссылка должна начинаться с http:// или https://")
            
            try:
                result = scanner.check_url(url)
                format_results(result)
            except Exception as e:
                print(f"Ошибка при проверке URL-ссылки: {e}")

        elif choice == '3':
            file_hash = input("Введите SHA-256 хеш: ").strip()
            if len(file_hash) != 64:
                print("Ошибка: Хеш SHA-256 должен содержать 64 символа")
                continue
            
            try:
                result = scanner.check_by_hash(file_hash)
                format_results(result)
            except Exception as e:
                print(f"Ошибка при проверке хеша: {e}")

        elif choice == '0':
            print("Выход из программы")
            break
        
        else:
            print("Неверный выбор. Попробуйте снова")

if __name__ == "__main__":
    main()