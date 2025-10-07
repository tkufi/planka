/*!
 * Copyright (c) 2024 PLANKA Software GmbH
 * Licensed under the Fair Use License: https://github.com/plankanban/planka/blob/master/LICENSE.md
 */

const { v4: uuid } = require('uuid');
const { rimraf } = require('rimraf');
const mime = require('mime');
const sharp = require('sharp');

module.exports = {
  inputs: {
    buffer: {
      type: 'ref',
      required: true,
    },
  },

  exits: {
    fileIsNotImage: {},
  },

  async fn(inputs) {
    const originalBuffer = inputs.buffer;
    var image = sharp(originalBuffer);

    let metadata;

    try {
      metadata = await image.metadata();

      if (metadata.orientation && metadata.orientation > 4) {
        image = image.rotate();
      }

      // originalBuffer = await image.toBuffer();
    } catch (error) {
      // await rimraf(inputs.file.fd);
      throw 'fileIsNotImage';
    }

    const fileManager = sails.hooks['file-manager'].getInstance();

    const extension = metadata.format === 'jpeg' ? 'jpg' : metadata.format;
    const size = originalBuffer.length;

    const mimeType = mime.getType(extension)

    const { id: uploadedFileId } = await UploadedFile.qm.createOne({
      mimeType,
      size,
      id: uuid(),
      type: UploadedFile.Types.USER_AVATAR,
    });

    const dirPathSegment = `${sails.config.custom.userAvatarsPathSegment}/${uploadedFileId}`;

    try {
      await fileManager.save(
        `${dirPathSegment}/original.${extension}`,
        originalBuffer,
        metadata.format,
      );

      const cover180Buffer = await image
        .resize(180, 180, {
          withoutEnlargement: true,
        })
        .png({
          quality: 75,
          force: false,
        })
        .toBuffer();

      await fileManager.save(
        `${dirPathSegment}/cover-180.${extension}`,
        cover180Buffer,
        metadata.format,
      );
    } catch (error) {
      sails.log.warn(error.stack);

      await fileManager.deleteDir(dirPathSegment);
      // await rimraf(inputs.file.fd);
      await UploadedFile.qm.deleteOne(uploadedFileId);

      throw 'fileIsNotImage';
    }

    // await rimraf(inputs.file.fd);

    return {
      uploadedFileId,
      extension,
      size,
    };
  },
};
