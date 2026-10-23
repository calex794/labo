#!/usr/bin/env python3
"""Apply reviewed WIE/RustJava J2ME fixes on pinned upstream Git commits."""
import hashlib
import sys
from pathlib import Path

EXPECTED = {
    "wie-midp/src/classes/javax/microedition/lcdui/image.rs":
        "073081f57694a05b3813bf561cf6f14f60a634c3",
    "rustjava-runtime/src/classes/java/lang/class.rs":
        "dd96d176432e0ca0c68f08c90ff6a86b0de832e2",
}


def replace_one(text, before, after, label):
    found = text.count(before)
    if found != 1:
        raise ValueError(f"{label}: expected exactly one occurrence; got {found}")
    return text.replace(before, after, 1)


def patch_image(src):
    src = replace_one(src, "use rustjava_runtime::classes::java::lang::String;",
                      "use rustjava_runtime::classes::java::{io::InputStream, lang::String};",
                      "Image import")
    anchor = '''                JavaMethodProto::new(
                    "createImage",
                    "(Ljava/lang/String;)Ljavax/microedition/lcdui/Image;",
                    Self::create_image_from_name,
                    MethodAccessFlags::PUBLIC | MethodAccessFlags::STATIC,
                ),'''
    new = '''                JavaMethodProto::new(
                    "createImage",
                    "(Ljava/io/InputStream;)Ljavax/microedition/lcdui/Image;",
                    Self::create_image_from_stream,
                    MethodAccessFlags::PUBLIC | MethodAccessFlags::STATIC,
                ),
''' + anchor
    src = replace_one(src, anchor, new, "Image.createImage(InputStream) registry")
    body = '''    async fn create_image_from_stream(
        jvm: &Jvm,
        _: &mut WieJvmContext,
        stream: ClassInstanceRef<InputStream>,
    ) -> JvmResult<ClassInstanceRef<Image>> {
        if stream.is_null() {
            return Err(jvm.exception("java/lang/NullPointerException", "image stream").await);
        }
        let data = JavaIoInputStream::read_until_end(jvm, &stream).await?;
        if data.len() > i32::MAX as usize {
            return Err(jvm.exception("java/io/IOException", "image stream is too large").await);
        }
        let mut image_array = jvm.instantiate_array("B", data.len()).await?;
        jvm.array_raw_buffer_mut(&mut image_array).await?.write(0, &data)?;
        jvm.invoke_static(
            "javax/microedition/lcdui/Image",
            "createImage",
            "([BII)Ljavax/microedition/lcdui/Image;",
            (image_array, 0, data.len() as i32),
        )
        .await
    }

'''
    src = replace_one(src, "    async fn create_image_from_data(\n",
                      body + "    async fn create_image_from_data(\n",
                      "Image.createImage(InputStream) implementation")
    anchor = '''    #[test]
    fn lbmp_images_preserve_grayscale_and_transparency_when_drawn() -> wie_util::Result<()> {'''
    test = '''    #[test]
    fn image_from_stream_reuses_decoder() -> wie_util::Result<()> {
        test_utils::run_jvm_test(Box::new([crate::get_protos().into()]), |jvm| async move {
            let mut data = b"LBMP".to_vec();
            for value in [8u32, 2, 9, 18, 0] {
                data.extend_from_slice(&value.to_le_bytes());
            }
            data.extend_from_slice(&[0xe0u8; 18]);
            let mut array = jvm.instantiate_array("B", data.len()).await?;
            jvm.array_raw_buffer_mut(&mut array).await?.write(0, &data)?;
            let stream = jvm.new_class("java/io/ByteArrayInputStream", "([B)V", (array,)).await?;
            let image: ClassInstanceRef<Image> = jvm.invoke_static(
                "javax/microedition/lcdui/Image",
                "createImage",
                "(Ljava/io/InputStream;)Ljavax/microedition/lcdui/Image;",
                (stream,),
            ).await?;
            let w: i32 = jvm.invoke_virtual(&image, "javax/microedition/lcdui/Image", "getWidth", "()I", ()).await?;
            let h: i32 = jvm.invoke_virtual(&image, "javax/microedition/lcdui/Image", "getHeight", "()I", ()).await?;
            assert_eq!((w, h), (2, 9));
            Ok(())
        })
    }

'''
    return replace_one(src, anchor, test + anchor, "image JVM regression test")


def patch_resource(src):
    src = replace_one(src, "use alloc::vec;", "use alloc::{string::ToString, vec};", "RustJava import")
    helper = '''fn resolve_class_resource_name(class_name: &str, name: &str) -> alloc::string::String {
    if let Some(absolute) = name.strip_prefix('/') {
        absolute.to_string()
    } else if let Some((package, _)) = class_name.rsplit_once('/') {
        let mut out = package.to_string();
        out.push('/');
        out.push_str(name);
        out
    } else {
        name.to_string()
    }
}

'''
    src = replace_one(src, "// class java.lang.Class\n",
                      helper + "// class java.lang.Class\n", "resource path helper")
    before = '''        tracing::debug!("java.lang.Class::getResourceAsStream({this:?}, {name:?})");

        let class_loader: ClassInstanceRef<ClassLoader> = jvm.get_field(&this, "java/lang/Class", "classLoader", "Ljava/lang/ClassLoader;").await?;'''
    after = '''        tracing::debug!("java.lang.Class::getResourceAsStream({this:?}, {name:?})");
        if name.is_null() {
            return Err(jvm.exception("java/lang/NullPointerException", "resource name").await);
        }
        let raw_name = JavaLangString::to_rust_string(jvm, &name).await?;
        let class_name = JavaLangClass::name(jvm, &this).await?;
        let resolved = resolve_class_resource_name(&class_name, &raw_name);
        let name = JavaLangString::from_rust_string(jvm, &resolved).await?;

        let class_loader: ClassInstanceRef<ClassLoader> = jvm.get_field(&this, "java/lang/Class", "classLoader", "Ljava/lang/ClassLoader;").await?;'''
    src = replace_one(src, before, after, "Class.getResourceAsStream relative paths")
    tests = '''
#[cfg(test)]
mod resource_path_tests {
    use super::resolve_class_resource_name;

    #[test]
    fn resource_path_relative_to_declaring_package() {
        assert_eq!(resolve_class_resource_name("game2048/scene/Logo", "images/logo.png"), "game2048/scene/images/logo.png");
        assert_eq!(resolve_class_resource_name("Main", "images/logo.png"), "images/logo.png");
    }

    #[test]
    fn absolute_path_ignores_package() {
        assert_eq!(resolve_class_resource_name("game2048/scene/Logo", "/images/logo.png"), "images/logo.png");
        assert_eq!(resolve_class_resource_name("game2048/scene/Logo", "/"), "");
    }
}
'''
    return src.rstrip() + "\n" + tests


def git_blob(text):
    value = text.encode("utf-8")
    return hashlib.sha1(b"blob " + str(len(value)).encode() + b"\0" + value).hexdigest()


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: patch_upstream.py <wie-root> <rustjava-root>")
    wie, rustjava = map(Path, sys.argv[1:])
    targets = [
        (wie, "wie-midp/src/classes/javax/microedition/lcdui/image.rs", patch_image),
        (rustjava, "rustjava-runtime/src/classes/java/lang/class.rs", patch_resource),
    ]
    replacements = []
    for root, relative, transform in targets:
        p = root / relative
        source = p.read_text()
        sha = git_blob(source)
        if sha != EXPECTED[relative]:
            raise ValueError(f"Refusing changed upstream file {p}: got {sha}, expected {EXPECTED[relative]}")
        replacements.append((p, transform(source)))
    for p, new in replacements:
        p.write_text(new)
        print(f"Patched {p}")
    print("J2ME image and resource patches applied; Rust compilation still required.")


if __name__ == "__main__":
    main()
