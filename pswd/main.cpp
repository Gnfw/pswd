#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <limits>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cstdint>
#include <cmath>
#include <random>
#include <map>


using namespace std;

// Функция для получения криптографически случайных байтов
vector<unsigned char> getCryptographicallyRandomBytes(size_t numBytes) {
    vector<unsigned char> randomBytes(numBytes);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dist(0, 255);

    for (size_t i = 0; i < numBytes; ++i) {
        randomBytes[i] = static_cast<unsigned char>(dist(gen));
    }
    return randomBytes;
}

// Функция для преобразования байтов в символы с равномерным распределением
string bytesToUniformChars(const vector<unsigned char>& bytes, const string& charset) {
    if (charset.empty()) throw runtime_error("CharSet is empty");
    if (bytes.empty()) return "";

    size_t charSetSize = charset.size();
    string result;

    for (size_t i = 0; i < bytes.size(); i += sizeof(uint64_t)) {
        uint64_t value = 0;
        for (size_t j = 0; j < sizeof(uint64_t) && (i + j) < bytes.size(); ++j) {
            value = (value << 8) | bytes[i + j];
        }
        while (value > 0) {
            result += charset[value % charSetSize];
            value /= charSetSize;
        }
    }
    return result;
}

// Функция для генерации криптографически случайного пароля
string generateStrongPassword(int length, const string& charset) {
    if (length <= 0) throw runtime_error("Password length must be positive");
    if (charset.empty()) throw runtime_error("Empty charset");

    size_t requiredBytes = static_cast<size_t>(ceil(length * 8.0 / 8.0));
    vector<unsigned char> randomBytes = getCryptographicallyRandomBytes(requiredBytes);
    if (randomBytes.empty()) return "";

    string password = bytesToUniformChars(randomBytes, charset);
    if (password.length() < length) {
        return generateStrongPassword(length, charset);
    }
    return password.substr(0, length);
}

// Функция для добавления разделителей
string addSeparators(const string& password, const string& separator, int groupSize) {
    if (groupSize <= 0) throw runtime_error("Group size must be positive.");
    if (password.empty()) return "";

    string result = "";
    for (size_t i = 0; i < password.length(); ++i) {
        result += password[i];
        if ((i + 1) % groupSize == 0 && (i + 1) != password.length()) {
            result += separator;
        }
    }
    return result;
}

// Функция для проверки надежности пароля (усиленная проверка)
int checkPasswordStrength(const string& password, double& entropy, double& timeToCrack) {
    if (password.length() < 8) return 1;
    bool hasLower = false, hasUpper = false, hasDigit = false, hasSpecial = false, hasAscii = false;
    const string specialChars = "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-=";

    int charSetSize = 0;

    for (char c : password) {
        if (islower(c)) hasLower = true;
        else if (isupper(c)) hasUpper = true;
        else if (isdigit(c)) hasDigit = true;
        else if (specialChars.find(c) != string::npos) hasSpecial = true;
        if (c >= 33 && c <= 126) hasAscii = true;
        charSetSize = static_cast<int>(pow(2, 8));
    }
    if (hasLower) charSetSize += 26;
    if (hasUpper) charSetSize += 26;
    if (hasDigit) charSetSize += 10;
    if (hasSpecial) charSetSize += specialChars.length();
    if (hasAscii) charSetSize = 94;

    if (charSetSize == 0) charSetSize = 1;

    int score = 0;
    if (hasLower) score++;
    if (hasUpper) score++;
    if (hasDigit) score++;
    if (hasSpecial) score++;
    if (hasAscii) score++;

    if (password.length() >= 24) score++;
    if (password.length() >= 32) score++;
    if (password.length() >= 48) score++;

    // Проверка на повторения
    for (size_t i = 0; i < password.length() - 2; ++i) {
        if (password[i] == password[i + 1] && password[i] == password[i + 2]) {
            return 1;
        }
    }

    entropy = static_cast<double>(password.length()) * log2(charSetSize);
    // Приблизительная оценка времени подбора. Основано на количестве возможных комбинаций и скорости перебора.
    double attemptsPerSecond = 10000000000.0; // Предполагаем 10 миллиардов попыток в секунду
    timeToCrack = pow(2, entropy) / attemptsPerSecond;

    if (score >= 8) return 5; // Ультра надежный
    if (score >= 7) return 4; // Очень надежный
    if (score >= 5) return 3; // Надежный
    if (score >= 3) return 2; // Средний
    return 1; // Слабый
}

// Функция для получения информации о надежности пароля в формате JSON
string getPasswordStrengthInfo(const string& password) {
    double entropy = 0.0;
    double timeToCrack = 0.0;
    int strength = checkPasswordStrength(password, entropy, timeToCrack);
    string strengthDescription;
    switch (strength) {
        case 1: strengthDescription = "Слабый"; break;
        case 2: strengthDescription = "Средний"; break;
        case 3: strengthDescription = "Надежный"; break;
        case 4: strengthDescription = "Очень надежный"; break;
        case 5: strengthDescription = "Ультра надежный"; break;
        default: strengthDescription = "Неизвестный"; break;
    }
    stringstream ss;
    ss << "{\"strength\": \"" << strengthDescription << "\", \"entropy\": \"" << fixed << setprecision(2) << entropy << "\", \"timeToCrack\": \"" << timeToCrack << "\"}";
    return ss.str();
}

// Битовые флаги для опций генерации
enum PasswordOptions {
    OPT_LOWERCASE = 1 << 0,
    OPT_UPPERCASE = 1 << 1,
    OPT_DIGITS = 1 << 2,
    OPT_SPECIAL = 1 << 3,
    OPT_NO_DIGITS = 1 << 4,
    OPT_SEPARATORS = 1 << 5,
    OPT_FULLASCII = 1 << 6,
    OPT_AVOID_SIMILAR = 1 << 7,
    OPT_NO_REPEAT = 1 << 8,
    OPT_RANDOM_CASE = 1 << 9,
    OPT_CUSTOM_CHARSET = 1 << 10,
    OPT_LANGUAGE_SPECIFIC = 1 << 11,
    OPT_OUTPUT_FORMAT = 1 << 12
};

// Функция для генерации пароля с заданными опциями
string generatePasswordWithOptions(int length, int options, const string& separator = "-", int groupSize = 4, const string& customCharset = "", const string& languageCharset = "", const string& outputFormat = "plain") {
    string charset = "";

    if (options & OPT_CUSTOM_CHARSET && !customCharset.empty()) {
        charset = customCharset;
    } else if (options & OPT_LANGUAGE_SPECIFIC && !languageCharset.empty()) {
        charset = languageCharset;
    } else if (options & OPT_FULLASCII) {
        for (int i = 33; i <= 126; ++i) {
            charset += static_cast<char>(i);
        }
    } else {
        if (options & OPT_LOWERCASE) charset += "abcdefghijklmnopqrstuvwxyz";
        if (options & OPT_UPPERCASE) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (options & OPT_DIGITS) charset += "0123456789";
        if (options & OPT_SPECIAL) charset += "!@#$%^&*()_+~`|}{[]\\:;\"'<>?,./-=";
        if (!(options & OPT_DIGITS) && (options & OPT_NO_DIGITS)) {
            string temp_charset = "";
            for (char c : charset) {
                if (!isdigit(c)) {
                    temp_charset += c;
                }
            }
            charset = temp_charset;
        }
        if (options & OPT_AVOID_SIMILAR) {
            string temp_charset = "";
            for (char c : charset) {
                if (c != 'l' && c != 'I' && c != '1' && c != '0' && c != 'O' && c != 'o') {
                    temp_charset += c;
                }
            }
            charset = temp_charset;
        }
    }

    string password = generateStrongPassword(length, charset);
    if (options & OPT_RANDOM_CASE) {
        string temp_password = "";
        auto randomBytes = getCryptographicallyRandomBytes(password.length());
        for (size_t i = 0; i < password.length(); i++) {
            unsigned char value = randomBytes[i];
            if (value % 2 == 0) {
                temp_password += tolower(password[i]);
            } else {
                temp_password += toupper(password[i]);
            }
        }
        password = temp_password;
    }
    if (options & OPT_SEPARATORS) {
        password = addSeparators(password, separator, groupSize);
    }

    if (options & OPT_NO_REPEAT) {
        string tempPassword = "";
        for (size_t i = 0; i < password.length(); i++) {
            bool repeat = false;
            for (size_t j = 0; j < tempPassword.length(); j++) {
                if (password[i] == tempPassword[j]) {
                    repeat = true;
                    break;
                }
            }
            if (!repeat) {
                tempPassword += password[i];
            }
        }
        password = tempPassword;
    }

    if (options & OPT_OUTPUT_FORMAT && outputFormat == "json") {
        stringstream ss;
        ss << "{\"password\": \"" << password << "\"}";
        return ss.str();
    }

    return password;
}

int main() {
    int passwordLength = 24;
    string separator = "-";
    int groupSize = 4;

    try {
        // 1. Пароль по умолчанию (все символы, с разделителями)
        cout << "1. Пароль по умолчанию (все символы, с разделителями):" << endl;
        int options1 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_DIGITS | OPT_SPECIAL | OPT_SEPARATORS;
        string password1 = generatePasswordWithOptions(passwordLength, options1, separator, groupSize);
        cout << "Сгенерированный пароль: " << password1 << endl;
        cout << "Длина пароля: " << password1.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password1) << endl;
        cout << "-----------------------------------" << endl;

        // 2. Пароль только из строчных букв, без разделителей
        cout << "2. Пароль только из строчных букв, без разделителей:" << endl;
        int options2 = OPT_LOWERCASE;
        string password2 = generatePasswordWithOptions(passwordLength, options2);
        cout << "Сгенерированный пароль: " << password2 << endl;
        cout << "Длина пароля: " << password2.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password2) << endl;
        cout << "-----------------------------------" << endl;

        // 3. Пароль из строчных букв и цифр, с разделителями
        cout << "3. Пароль из строчных букв и цифр, с разделителями:" << endl;
        int options3 = OPT_LOWERCASE | OPT_DIGITS | OPT_SEPARATORS;
        string password3 = generatePasswordWithOptions(passwordLength, options3, separator, groupSize);
        cout << "Сгенерированный пароль: " << password3 << endl;
        cout << "Длина пароля: " << password3.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password3) << endl;
        cout << "-----------------------------------" << endl;

        // 4. Пароль без цифр и с разделителями, только из спецсимволов
        cout << "4. Пароль без цифр и с разделителями, только из спецсимволов:" << endl;
        int options4 = OPT_SPECIAL | OPT_NO_DIGITS | OPT_SEPARATORS;
        string password4 = generatePasswordWithOptions(passwordLength, options4, separator, groupSize);
        cout << "Сгенерированный пароль: " << password4 << endl;
        cout << "Длина пароля: " << password4.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password4) << endl;
        cout << "-----------------------------------" << endl;

        // 5. Пароль только из прописных букв и цифр
        cout << "5. Пароль только из прописных букв и цифр:" << endl;
        int options5 = OPT_UPPERCASE | OPT_DIGITS;
        string password5 = generatePasswordWithOptions(passwordLength, options5);
        cout << "Сгенерированный пароль: " << password5 << endl;
        cout << "Длина пароля: " << password5.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password5) << endl;
        cout << "-----------------------------------" << endl;

        // 6. Пароль из полного ASCII набора, с разделителями
        cout << "6. Пароль из полного ASCII набора, с разделителями:" << endl;
        int options6 = OPT_FULLASCII | OPT_SEPARATORS;
        string password6 = generatePasswordWithOptions(passwordLength, options6, separator, groupSize);
        cout << "Сгенерированный пароль: " << password6 << endl;
        cout << "Длина пароля: " << password6.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password6) << endl;
        cout << "-----------------------------------" << endl;

        // 7. Пароль без похожих символов
        cout << "7. Пароль без похожих символов:" << endl;
        int options7 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_DIGITS | OPT_SPECIAL | OPT_AVOID_SIMILAR;
        string password7 = generatePasswordWithOptions(passwordLength, options7);
        cout << "Сгенерированный пароль: " << password7 << endl;
        cout << "Длина пароля: " << password7.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password7) << endl;
        cout << "-----------------------------------" << endl;

        // 8. Пароль без повторяющихся символов
        cout << "8. Пароль без повторяющихся символов:" << endl;
        int options8 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_DIGITS | OPT_SPECIAL | OPT_NO_REPEAT;
        string password8 = generatePasswordWithOptions(passwordLength, options8);
        cout << "Сгенерированный пароль: " << password8 << endl;
        cout << "Длина пароля: " << password8.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password8) << endl;
        cout << "-----------------------------------" << endl;

        // 9. Пароль со случайным регистром
        cout << "9. Пароль со случайным регистром:" << endl;
        int options9 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_DIGITS | OPT_SPECIAL | OPT_RANDOM_CASE;
        string password9 = generatePasswordWithOptions(passwordLength, options9);
        cout << "Сгенерированный пароль: " << password9 << endl;
        cout << "Длина пароля: " << password9.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password9) << endl;
        cout << "-----------------------------------" << endl;

        // 10. Пароль с пользовательским набором символов
        cout << "10. Пароль с пользовательским набором символов (пример 'abc123!@#') :" << endl;
        int options10 = OPT_CUSTOM_CHARSET;
        string customCharset = "abc123!@#";
        string password10 = generatePasswordWithOptions(passwordLength, options10, separator, groupSize, customCharset);
        cout << "Сгенерированный пароль: " << password10 << endl;
        cout << "Длина пароля: " << password10.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password10) << endl;
        cout << "-----------------------------------" << endl;

        // 11. Пароль с поддержкой различных языков (пример 'русский')
        cout << "11. Пароль с поддержкой различных языков (пример 'русский'):" << endl;
        int options11 = OPT_LANGUAGE_SPECIFIC;
        string languageCharset = "абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        string password11 = generatePasswordWithOptions(passwordLength, options11, separator, groupSize, "", languageCharset);
        cout << "Сгенерированный пароль: " << password11 << endl;
        cout << "Длина пароля: " << password11.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password11) << endl;
        cout << "-----------------------------------" << endl;

        // 12. Пароль с поддержкой различных форматов вывода (пример JSON)
        cout << "12. Пароль с поддержкой различных форматов вывода (пример JSON):" << endl;
        int options12 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_DIGITS | OPT_SPECIAL | OPT_OUTPUT_FORMAT;
        string outputFormat = "json";
        string password12 = generatePasswordWithOptions(passwordLength, options12, separator, groupSize, "", "", outputFormat);
        cout << "Сгенерированный пароль: " << password12 << endl;
        cout << "Длина пароля: " << password12.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password12) << endl;
        cout << "-----------------------------------" << endl;

        // 13. Пароль с использованием только специальных символов и цифр
        cout << "13. Пароль с использованием только специальных символов и цифр:" << endl;
        int options13 = OPT_SPECIAL | OPT_DIGITS;
        string password13 = generatePasswordWithOptions(passwordLength, options13);
        cout << "Сгенерированный пароль: " << password13 << endl;
        cout << "Длина пароля: " << password13.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password13) << endl;
        cout << "-----------------------------------" << endl;

        // 14. Пароль с использованием только строчных букв и специальных символов
        cout << "14. Пароль с использованием только строчных букв и специальных символов:" << endl;
        int options14 = OPT_LOWERCASE | OPT_SPECIAL;
        string password14 = generatePasswordWithOptions(passwordLength, options14);
        cout << "Сгенерированный пароль: " << password14 << endl;
        cout << "Длина пароля: " << password14.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password14) << endl;
        cout << "-----------------------------------" << endl;

        // 15. Пароль с использованием только прописных букв и специальных символов
        cout << "15. Пароль с использованием только прописных букв и специальных символов:" << endl;
        int options15 = OPT_UPPERCASE | OPT_SPECIAL;
        string password15 = generatePasswordWithOptions(passwordLength, options15);
        cout << "Сгенерированный пароль: " << password15 << endl;
        cout << "Длина пароля: " << password15.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password15) << endl;
        cout << "-----------------------------------" << endl;

        // 16. Пароль с использованием только строчных букв, прописных букв и цифр
        cout << "16. Пароль с использованием только строчных букв, прописных букв и цифр:" << endl;
        int options16 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_DIGITS;
        string password16 = generatePasswordWithOptions(passwordLength, options16);
        cout << "Сгенерированный пароль: " << password16 << endl;
        cout << "Длина пароля: " << password16.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password16) << endl;
        cout << "-----------------------------------" << endl;

        // 17. Пароль с использованием только строчных букв, прописных букв и специальных символов
        cout << "17. Пароль с использованием только строчных букв, прописных букв и специальных символов:" << endl;
        int options17 = OPT_LOWERCASE | OPT_UPPERCASE | OPT_SPECIAL;
        string password17 = generatePasswordWithOptions(passwordLength, options17);
        cout << "Сгенерированный пароль: " << password17 << endl;
        cout << "Длина пароля: " << password17.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password17) << endl;
        cout << "-----------------------------------" << endl;

        // 18. Пароль с использованием только цифр и специальных символов, с разделителями
        cout << "18. Пароль с использованием только цифр и специальных символов, с разделителями:" << endl;
        int options18 = OPT_DIGITS | OPT_SPECIAL | OPT_SEPARATORS;
        string password18 = generatePasswordWithOptions(passwordLength, options18, separator, groupSize);
        cout << "Сгенерированный пароль: " << password18 << endl;
        cout << "Длина пароля: " << password18.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password18) << endl;
        cout << "-----------------------------------" << endl;

        // 19. Пароль с использованием только строчных букв и специальных символов, с разделителями
        cout << "19. Пароль с использованием только строчных букв и специальных символов, с разделителями:" << endl;
        int options19 = OPT_LOWERCASE | OPT_SPECIAL | OPT_SEPARATORS;
        string password19 = generatePasswordWithOptions(passwordLength, options19, separator, groupSize);
        cout << "Сгенерированный пароль: " << password19 << endl;
        cout << "Длина пароля: " << password19.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password19) << endl;
        cout << "-----------------------------------" << endl;

        // 20. Пароль с использованием только прописных букв и специальных символов, с разделителями
        cout << "20. Пароль с использованием только прописных букв и специальных символов, с разделителями:" << endl;
        int options20 = OPT_UPPERCASE | OPT_SPECIAL | OPT_SEPARATORS;
        string password20 = generatePasswordWithOptions(passwordLength, options20, separator, groupSize);
        cout << "Сгенерированный пароль: " << password20 << endl;
        cout << "Длина пароля: " << password20.length() << " символов." << endl;
        cout << "Информация о надежности: " << getPasswordStrengthInfo(password20) << endl;
        cout << "-----------------------------------" << endl;

    } catch (const exception& ex) {
        cerr << "Ошибка генерации пароля: " << ex.what() << endl;
        return 1;
    }
    return 0;
}
