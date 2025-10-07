/*!
 * Copyright (c) 2024 PLANKA Software GmbH
 * Licensed under the Fair Use License: https://github.com/plankanban/planka/blob/master/LICENSE.md
 */

const { URL } = require('url');
const icoToPng = require('ico-to-png');
const sharp = require('sharp');

const FETCH_TIMEOUT = 4000;
const MAX_RESPONSE_LENGTH = 1024 * 1024;

const FAVICON_TAGS_REGEX = /<link [^>]*rel="([^"]* )?icon( [^"]*)?"[^>]*>/gi;
const HREF_REGEX = /href="(.*?)"/i;
const SIZES_REGEX = /sizes="(.*?)"/i;

const fetchWithTimeout = (url) => {
  const abortController = new AbortController();
  setTimeout(() => abortController.abort(), FETCH_TIMEOUT);

  return fetch(url, {
    signal: abortController.signal,
  });
};

const readResponse = async (response) => {
  const reader = response.body.getReader();

  const chunks = [];
  let receivedLength = 0;

  for (; ;) {
    const { value, done } = await reader.read(); // eslint-disable-line no-await-in-loop

    if (done) {
      break;
    }

    chunks.push(value);
    receivedLength += value.length;

    if (receivedLength > MAX_RESPONSE_LENGTH) {
      reader.cancel();

      return {
        ok: false,
        buffer: Buffer.concat(chunks),
      };
    }
  }

  return {
    ok: true,
    buffer: Buffer.concat(chunks),
  };
};

const isWantedFaviconTag = (faviconTag) => {
  const sizesMatch = faviconTag.match(SIZES_REGEX);

  if (!sizesMatch) {
    return false;
  }

  const sizes = sizesMatch[1].split('x');
  return parseInt(sizes[0], 10) >= 32 && parseInt(sizes[1], 10) >= 32;
};

module.exports = {
  inputs: {
    url: {
      type: 'string',
      required: true,
    },
  },

  async fn(inputs) {
    let response;
    let readedResponse;

    try {
      response = await fetchWithTimeout(inputs.url);
      if (!response.ok) {
        return;
      }

      readedResponse = await readResponse(response);
    } catch (error) {
      return;
    }

    return readedResponse.buffer;
  },
};
