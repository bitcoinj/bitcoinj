/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.walletfx.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.Writer;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import javafx.scene.image.Image;
import javafx.scene.image.WritableImage;
import javafx.scene.paint.Color;

/**
 * Utility for creating Images from QR Codes
 */
public class QRCodeImages {
    /**
     * Create an Image from a Bitcoin URI
     * @param uri Bitcoin URI
     * @param width width of image
     * @param height height of image
     * @return a javafx Image
     */
    public static Image imageFromString(String uri, int width, int height) {
        return imageFromMatrix(matrixFromString(uri, width, height));
    }

    /**
     * Create a BitMatrix from a Bitcoin URI
     * @param uri Bitcoin URI
     * @return A BitMatrix for the QRCode for the URI
     */
    private static BitMatrix matrixFromString(String uri, int width, int height) {
        Writer qrWriter = new QRCodeWriter();
        BitMatrix matrix;
        try {
            matrix = qrWriter.encode(uri, BarcodeFormat.QR_CODE, width, height);
        } catch (WriterException e) {
            throw new RuntimeException(e);
        }
        return matrix;
    }

    /**
     * Create a JavaFX Image from a BitMatrix
     * @param matrix the matrix
     * @return the QRCode Image
     */
    private static Image imageFromMatrix(BitMatrix matrix) {
        int height = matrix.getHeight();
        int width = matrix.getWidth();
        WritableImage image = new WritableImage(width, height);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                Color color = matrix.get(x,y) ? Color.BLACK : Color.WHITE;
                image.getPixelWriter().setColor(x, y, color);
            }
        }
        return image;
    }
}
