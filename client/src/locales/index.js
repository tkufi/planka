/*!
 * Copyright (c) 2024 PLANKA Software GmbH
 * Licensed under the Fair Use License: https://github.com/plankanban/planka/blob/master/LICENSE.md
 */

import keyBy from 'lodash/keyBy';

import arYE from './ar-YE';
import bgBG from './bg-BG';
import csCZ from './cs-CZ';
import daDK from './da-DK';
import deDE from './de-DE';
import elGR from './el-GR';
import enGB from './en-GB';
import fiFI from './fi-FI';
import svSE from './sv-SE';

const locales = [
  arYE,
  bgBG,
  csCZ,
  daDK,
  deDE,
  elGR,
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
