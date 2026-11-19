/*
 * Copyright 2019 Tim Straser.
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

package org.bitcoinj.utils;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.util.List;

public class BlockFileLoaderTest {

    private final File TEST_DIRECTORY = new File("./test");

    private final File TEST_FILE = new File("./test/blk00000.dat");

    private final File TEST_FILE2 = new File("./test/blk00001.dat");

    @Before
    public void setup() {
        TEST_DIRECTORY.mkdir();
    }

    @Test
    public void testGetReferenceClientBlockFileListNoFiles() {
        List<File> files = BlockFileLoader.getReferenceClientBlockFileList(TEST_DIRECTORY);
        Assert.assertTrue(files.isEmpty());
    }

    @Test
    public void testGetReferenceClientBlockFileListOneFile() {
        try {
            FileWriter fw = new FileWriter(TEST_FILE);
            fw.write("test");
            fw.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        List<File> files = BlockFileLoader.getReferenceClientBlockFileList(TEST_DIRECTORY);
        Assert.assertEquals(1, files.size());
    }

    @Test
    public void testGetReferenceClientBlockFileListMultipleFiles() {
        try {
            FileWriter fw = new FileWriter(TEST_FILE);
            FileWriter fw2 = new FileWriter(TEST_FILE2);
            fw.write("test");
            fw2.write("test2");
            fw.close();
            fw2.close();
        } catch (Exception e) {
            System.out.println(e);
        }
        List<File> files = BlockFileLoader.getReferenceClientBlockFileList(TEST_DIRECTORY);
        Assert.assertEquals(2, files.size());
    }


    @After
    public void cleanUp() {
        TEST_FILE.delete();
        TEST_FILE2.delete();
        TEST_DIRECTORY.delete();
    }
}
