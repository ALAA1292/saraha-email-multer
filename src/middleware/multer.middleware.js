import multer from 'multer'
import fs from 'node:fs'
import crypto from 'node:crypto'
import { fileTypeFromFile } from 'file-type';
import { allowedExtension } from '../Common/Constants.js';
import { BadRequestException } from '../Utils/Security/Errors/exceptions.error.js';

export const multerUpload = ({ desiredPath }) => {

    //validate if the destination exists

    const fullDestinationPath = `uploads/${desiredPath}`;
    if (!fs.existsSync(fullDestinationPath)) {
        fs.mkdirSync(fullDestinationPath, { recursive: true })
    }


    //storage
    const storage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, fullDestinationPath)
        },
        filename: function (req, file, cb) {
            const suffix = crypto.randomBytes(5).toString('hex') + Date.now()
            cb(null, `${suffix} __ ${file.originalname}`)
        }
    })


    //file filter 

    const fileFilter = async (req, file, cb) => {
        const [fileType, inputFileExtention] = file.mimetype.split("/");
        const fileExtensions = allowedExtension[fileType]


        if (fileExtensions.includes(inputFileExtention)) {
            cb(null, true)
        } else {
            cb(new BadRequestException("invalid file extnesion"), false)
        }
    }

    return multer({ fileFilter, storage })
}



export const validateImage = async (req, res, next) => {
    const file = req.file;
    if (!file) {
        throw new BadRequestException('Image is required', null, 'MISSING_IMAGE');
    }

    const type = await fileTypeFromFile(file.path);
    if (!type || !['image/png', 'image/jpeg', 'image/webp'].includes(type.mime)) {
        await fs.promises.unlink(file.path).catch(() => { });
        console.log({ "type": type })

        throw new BadRequestException('Invalid image content', { detected: type ? type.mime : 'unknown' }, "INVALID_IMAGE_CONTENT");
    }

    next();

};