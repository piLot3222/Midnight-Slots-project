// Midnight Slots — ESP32 DevKit
// Красный LED проигрыша: GPIO 21 -> резистор -> GND
// Кнопка: GPIO 19 -> кнопка -> GND
// Пассивный буззер: GPIO 18 -> GND
// Зелёный LED выигрыша: GPIO 22 -> резистор -> GND

const int RED_LED_PIN = 21;
const int BUTTON_PIN = 19;
const int BUZZER_PIN = 18;
const int GREEN_LED_PIN = 22;

const unsigned long DEBOUNCE_MS = 45;

bool lastRawButton = HIGH;
bool stableButton = HIGH;
unsigned long lastButtonChange = 0;

enum ResultMode {
  RESULT_IDLE,
  RESULT_WIN,
  RESULT_LOSE
};

ResultMode resultMode = RESULT_IDLE;
int resultStep = 0;
unsigned long nextResultAction = 0;

const int winNotes[] = {988, 1245, 1480, 1760, 2093, 2637};
const int loseNotes[] = {220, 196, 165};

void allLedsOff() {
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);
}

void startWin() {
  digitalWrite(RED_LED_PIN, LOW);
  digitalWrite(GREEN_LED_PIN, LOW);
  noTone(BUZZER_PIN);

  resultMode = RESULT_WIN;
  resultStep = 0;
  nextResultAction = 0;
}

void startLose() {
  digitalWrite(GREEN_LED_PIN, LOW);
  digitalWrite(RED_LED_PIN, LOW);
  noTone(BUZZER_PIN);

  resultMode = RESULT_LOSE;
  resultStep = 0;
  nextResultAction = 0;
}

void updateResult(unsigned long now) {
  if (resultMode == RESULT_IDLE || now < nextResultAction) {
    return;
  }

  if (resultMode == RESULT_WIN) {
    if (resultStep == 12) {
      digitalWrite(GREEN_LED_PIN, LOW);
      noTone(BUZZER_PIN);
      resultMode = RESULT_IDLE;
      return;
    }

    if (resultStep < 12) {
      if (resultStep % 2 == 0) {
        digitalWrite(GREEN_LED_PIN, HIGH);
        tone(BUZZER_PIN, winNotes[resultStep / 2], 120);
      } else {
        digitalWrite(GREEN_LED_PIN, LOW);
        noTone(BUZZER_PIN);
      }

      resultStep++;
      nextResultAction = now + 100;
      return;
    }

    digitalWrite(GREEN_LED_PIN, HIGH);
    nextResultAction = now + 1200;
    return;
  }

  if (resultMode == RESULT_LOSE) {
    if (resultStep == 8) {
      digitalWrite(RED_LED_PIN, LOW);
      noTone(BUZZER_PIN);
      resultMode = RESULT_IDLE;
      return;
    }

    if (resultStep < 8) {
      if (resultStep % 2 == 0) {
        digitalWrite(RED_LED_PIN, HIGH);
        tone(BUZZER_PIN, loseNotes[resultStep / 2], 240);
      } else {
        digitalWrite(RED_LED_PIN, LOW);
        noTone(BUZZER_PIN);
      }

      resultStep++;
      nextResultAction = now + 190;
      return;
    }

    digitalWrite(RED_LED_PIN, HIGH);
    nextResultAction = now + 1200;
    return;
  }
}

void handleSerialCommand(String command) {
  command.trim();

  if (command == "WIN") {
    startWin();
  } else if (command == "LOSE") {
    startLose();
  }
}

void readButton(unsigned long now) {
  bool rawButton = digitalRead(BUTTON_PIN);

  if (rawButton != lastRawButton) {
    lastRawButton = rawButton;
    lastButtonChange = now;
  }

  if (now - lastButtonChange >= DEBOUNCE_MS &&
      rawButton != stableButton) {
    stableButton = rawButton;

    // Одно нажатие = один SPIN.
    if (stableButton == LOW) {
      Serial.println("SPIN");
    }
  }
}

void setup() {
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(GREEN_LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(BUZZER_PIN, OUTPUT);

  allLedsOff();
  noTone(BUZZER_PIN);

  Serial.begin(115200);
  Serial.setTimeout(20);

  // Проверка красного LED
  digitalWrite(RED_LED_PIN, HIGH);
  delay(300);
  digitalWrite(RED_LED_PIN, LOW);

  // Проверка зелёного LED
  digitalWrite(GREEN_LED_PIN, HIGH);
  delay(300);
  digitalWrite(GREEN_LED_PIN, LOW);
}

void loop() {
  unsigned long now = millis();

  while (Serial.available() > 0) {
    String command = Serial.readStringUntil('\n');
    handleSerialCommand(command);
  }

  // Кнопка проверяется на каждом проходе loop().
  readButton(now);

  // Индикация результата не блокирует чтение кнопки.
  updateResult(now);
}
