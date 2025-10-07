/*!
 * Copyright (c) 2024 PLANKA Software GmbH
 * Licensed under the Fair Use License: https://github.com/plankanban/planka/blob/master/LICENSE.md
 */

import keyBy from 'lodash/keyBy';

import enGB from './en-GB';
import fiFI from './fi-FI';
import svSE from './sv-SE';

const locales = [
  enGB,
  fiFI,
  svSE,
];

export default locales;

export const languages = locales.map((locale) => locale.language);

export const embeddedLocales = locales.reduce(
  (result, locale) => ({
    ...result,
    [locale.language]: locale.embeddedLocale,
  }),
  {},
);

export const localeByLanguage = keyBy(locales, 'language');
