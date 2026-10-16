(() => {
  'use strict';
  const preferred = navigator.languages?.[0] || navigator.language || 'en';
  const p = String(preferred).toLowerCase();
  const lang = /^zh(?:[-_]|$)/.test(p) ? 'zh' : /^uk(?:[-_]|$)/.test(p) ? 'uk' : 'en';
  const messages = {
    zh: {
      title: 'UID 过滤', refresh: '刷新模块状态', enable: '启用过滤', loading: '正在读取模块状态…',
      scope: '生效应用', defaults: '加入内置包名', scopeHelp: '仅对下列包名生效，支持添加或移除。',
      inputLabel: '添加应用包名', placeholder: '例如 com.example.app', add: '添加', listLabel: '生效应用列表',
      emptyTitle: '还没有生效应用', emptyHelp: '输入包名，或加入内置包名。', about: '使用说明',
      aboutBefore: '通过过滤指定包的 ', aboutAfter: ' 做到规避检测。',
      applyHelp: '保存并应用只停止配置有变化的目标应用，重新打开后生效。列表外的应用不受影响，应用数据不会清除。',
      connecting: '正在连接模块', save: '保存并应用', builtin: '内置', remove: '移除 {package}',
      removed: '已从列表移除，保存后生效。', processing: '正在处理…', wait: '请稍候', disconnected: '尚未连接模块',
      unsaved: '有未保存的更改', saved: '配置已保存', selected: '已选择 {count} 个应用', selectedOne: '已选择 {count} 个应用',
      pendingSave: '，等待保存', disablePending: '保存后关闭过滤', disabled: '过滤已关闭',
      updateNotice: '更新待重启：请重启手机加载新版模块。',
      disabledNotice: '模块已被管理器停用。启用过滤并保存后，会同时启用本模块。',
      missingBridge: '请从模块管理器的 WebUI 打开此面板。', timeout: '操作超时，请刷新状态确认结果。',
      operationFailed: '模块操作失败', invalidResponse: '模块返回的数据无效，请重新打开面板。',
      invalidConfig: '模块配置格式不正确。', saveBeforeRefresh: '请先保存当前更改，再刷新状态。',
      invalidPackage: '请输入完整包名，例如 com.example.app。', duplicate: '这个包名已经在列表中。',
      limit: '最多可添加 128 个包名。', added: '已添加，保存后生效。', toggleChanged: '点击“保存并应用”使更改生效。',
      defaultsAdded: '内置包名已加入列表，保存后生效。', emptyScope: '请至少添加一个生效包名。',
      saving: '正在保存并应用更改…', savedReboot: '配置已保存。重启手机加载新版模块后生效。',
      applied: '已保存并应用，重新打开所选应用即可。'
    },
    en: {
      title: 'UID Filter', refresh: 'Refresh module status', enable: 'Enable filtering', loading: 'Reading module status…',
      scope: 'Target apps', defaults: 'Add defaults', scopeHelp: 'Filtering applies only to the packages listed below. Add or remove packages as needed.',
      inputLabel: 'Add a package name', placeholder: 'e.g. com.example.app', add: 'Add', listLabel: 'Target package list',
      emptyTitle: 'No target apps yet', emptyHelp: 'Enter a package name or add the defaults.', about: 'How to use',
      aboutBefore: 'Filters ', aboutAfter: ' calls in selected apps to avoid detection.',
      applyHelp: 'Save & apply stops only apps whose filtering state has changed. Reopen them to apply the changes. Apps outside this list are unaffected. App data is preserved.',
      connecting: 'Connecting to module', save: 'Save & apply', builtin: 'Built-in', remove: 'Remove {package}',
      removed: 'Package removed. Save to apply.', processing: 'Working…', wait: 'Please wait', disconnected: 'Module not connected',
      unsaved: 'Unsaved changes', saved: 'Configuration saved', selected: '{count} apps selected', selectedOne: '{count} app selected',
      pendingSave: ' · Save to apply', disablePending: 'Save to turn filtering off', disabled: 'Filtering is off',
      updateNotice: 'Update pending. Restart your phone to load the new module.',
      disabledNotice: 'The module is disabled in your manager. Turn filtering on and save to enable it.',
      missingBridge: 'Open this panel from your module manager’s WebUI.', timeout: 'The operation timed out. Refresh the status to check the result.',
      operationFailed: 'Module operation failed', invalidResponse: 'Invalid response from the module. Reopen this panel.',
      invalidConfig: 'The module configuration is invalid.', saveBeforeRefresh: 'Save your changes before refreshing.',
      invalidPackage: 'Enter a full package name, such as com.example.app.', duplicate: 'This package is already in the list.',
      limit: 'You can add up to 128 package names.', added: 'Package added. Save to apply.', toggleChanged: 'Select “Save & apply” to apply your changes.',
      defaultsAdded: 'Default packages added. Save to apply.', emptyScope: 'Add at least one target package.',
      saving: 'Saving and applying changes…', savedReboot: 'Configuration saved. Restart your phone to load the new module.',
      applied: 'Saved and applied. Reopen the selected apps.'
    },
    uk: {
      title: 'Фільтр UID', refresh: 'Оновити стан модуля', enable: 'Увімкнути фільтрацію', loading: 'Зчитування стану модуля…',
      scope: 'Цільові додатки', defaults: 'Додати типові', scopeHelp: 'Фільтрація діє лише для пакетів зі списку нижче. Додавайте або видаляйте пакети за потреби.',
      inputLabel: 'Додати назву пакета', placeholder: 'напр. com.example.app', add: 'Додати', listLabel: 'Список цільових пакетів',
      emptyTitle: 'Цільових додатків ще немає', emptyHelp: 'Введіть назву пакета або додайте типові.', about: 'Як користуватися',
      aboutBefore: 'Фільтрує виклики ', aboutAfter: ' у вибраних додатках, щоб уникнути виявлення.',
      applyHelp: 'Збереження й застосування зупиняє лише ті додатки, для яких змінився стан фільтрації. Відкрийте їх знову, щоб зміни набули чинності. Додатки поза списком не зачіпаються. Дані додатків зберігаються.',
      connecting: 'Підключення до модуля', save: 'Зберегти й застосувати', builtin: 'Вбудований', remove: 'Видалити {package}',
      removed: 'Пакет видалено. Збережіть, щоб застосувати.', processing: 'Обробка…', wait: 'Зачекайте', disconnected: 'Модуль не підключено',
      unsaved: 'Є незбережені зміни', saved: 'Конфігурацію збережено', selected: 'Вибрано додатків: {count}', selectedOne: 'Вибрано додатків: {count}',
      pendingSave: ' · Збережіть, щоб застосувати', disablePending: 'Збережіть, щоб вимкнути фільтрацію', disabled: 'Фільтрацію вимкнено',
      updateNotice: 'Очікується оновлення. Перезавантажте телефон, щоб завантажити новий модуль.',
      disabledNotice: 'Модуль вимкнено в менеджері. Увімкніть фільтрацію та збережіть, щоб увімкнути його.',
      missingBridge: 'Відкрийте цю панель із WebUI вашого менеджера модулів.', timeout: 'Час очікування операції вичерпано. Оновіть стан, щоб перевірити результат.',
      operationFailed: 'Помилка операції модуля', invalidResponse: 'Модуль повернув недійсну відповідь. Відкрийте панель знову.',
      invalidConfig: 'Конфігурація модуля недійсна.', saveBeforeRefresh: 'Збережіть зміни перед оновленням.',
      invalidPackage: 'Введіть повну назву пакета, наприклад com.example.app.', duplicate: 'Цей пакет уже є у списку.',
      limit: 'Можна додати не більше 128 пакетів.', added: 'Пакет додано. Збережіть, щоб застосувати.', toggleChanged: 'Натисніть «Зберегти й застосувати», щоб застосувати зміни.',
      defaultsAdded: 'Типові пакети додано. Збережіть, щоб застосувати.', emptyScope: 'Додайте принаймні один цільовий пакет.',
      saving: 'Збереження та застосування змін…', savedReboot: 'Конфігурацію збережено. Перезавантажте телефон, щоб завантажити новий модуль.',
      applied: 'Збережено й застосовано. Відкрийте вибрані додатки знову.'
    }
  };
  const t = (key, values = {}) => (messages[lang][key] ?? messages.en[key] ?? key)
    .replace(/\{(\w+)\}/g, (match, name) => values[name] ?? match);
  document.documentElement.lang = lang === 'zh' ? 'zh-CN' : lang;
  document.title = t('title') + ' · 泷泽';
  document.querySelectorAll('[data-i18n]').forEach(node => { node.textContent = t(node.dataset.i18n); });
  for (const attribute of ['aria-label', 'title', 'placeholder']) {
    document.querySelectorAll('[data-i18n-' + attribute + ']').forEach(node => {
      node.setAttribute(attribute, t(node.getAttribute('data-i18n-' + attribute)));
    });
  }
  window.CQUidI18n = { lang, t };
})();
