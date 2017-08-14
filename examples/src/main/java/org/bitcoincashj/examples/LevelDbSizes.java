/*
 * Copyright 2016 Robin Owens
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

package org.bitcoincashj.examples;

import static org.fusesource.leveldbjni.JniDBFactory.*;

import java.io.File;
import java.io.IOException;

import org.iq80.leveldb.DB;
import org.iq80.leveldb.Options;
import org.iq80.leveldb.Range;

public class LevelDbSizes {

    public static void main(String[] args) throws Exception {
        DB db = null;
        Options options = new Options();
        options.createIfMissing(false);
        try {
            db = factory.open(new File(args[0]), options);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Thread.sleep(100000);
        for (int i = 0; i < 10; i++) {
            byte[] from = new byte[1];
            from[0] = (byte) i;
            byte[] to = new byte[1];
            to[0] = (byte) (i + 1);

            long[] sizes = db.getApproximateSizes(new Range(from, to));
            System.out.println("From:" + i + " to:" + (i + 1) + " Size: "
                    + sizes[0]);
        }
        byte[] from = new byte[1];
        from[0] = 0;
        byte[] to = new byte[1];
        to[0] = -128;

        long[] sizes = db.getApproximateSizes(new Range(from, to));
        System.out.println("Size: " + sizes[0]);
        String stats = db.getProperty("leveldb.stats");
        System.out.println(stats);
        db.close();
    }

}
